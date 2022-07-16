"""
This is the Passcrow monitoring tool. It maintains a local idea of one
or more Passcrow servers' health and availability.

Usage:

    $ python3 -m passcrow.mon /path/to/workdir <operation> <arguments ...>

Operations:

    Auto  <op> <op-args>    Peform an op for all servers in servers.json
    Stats <servernames>     Update our local mirror of the server stats
    Summarize [<outfile>]   Outputs a JSON summary of server states

    ETest <servername> <ttl> <email>
    RTest <servername> <ttl> <imap-server> <username> <password>

Note: the working directory must exist already and be writable by the
      monitoring process.

The `ETest` operation will test putting data in escrow, with a given
time-to-live (in days). It will only ever keep one escrow request for
any given TTL, and will only create a new one when the previous one has
expired.

The `RTest` op will test recovering data from escrow, checking the
given IMAP account's inbox for verification requests.
"""
import json
import os
import random
import threading
import time
import traceback
import sys
import urllib.request
try:
    import imapclient
except:
    imapclient = None

from .client import PasscrowRecoveryPolicy, PasscrowClient


MAX_SERVER_STATS_BYTES = 10240    # We don't want to process infinite data


def _load_server_list(workdir):
    try:
        with open(os.path.join(workdir, 'servers.json'), 'rb') as fd:
            return json.load(fd)
    except Exception as e:
        _bail_out('Failed to load servers.json: %s' % e)


def _load_server_stats(workdir, server):
    try:
        with open(os.path.join(workdir, server, 'status.json'), 'rb') as fd:
            data = fd.read(MAX_SERVER_STATS_BYTES)
            data = json.loads(data)
        data['server'] = server
        return data
    except:
        return {'server': server}


def _history(status, which):
    if 'history' not in status:
        status['history_begins'] = int(time.time())
        status['history'] = {}
    if which not in status['history']:
        status['history'][which] = []
    return status['history'][which]


def _add_history(status, which, datapoint, keep=50):
    points = _history(status, which)
    points.append(datapoint)
    while len(points) > keep:
        # Randomly discard one datapoint, from the oldest 3/4 we have.
        drop = random.randint(0, (3*keep)//4)
        points[drop:drop+1] = []
    points = sorted(points)
    status['history'][which+'_avg'] = sum(points) // len(points)
    status['history'][which+'_m50'] = points[len(points)//2]
    status['history'][which+'_m90'] = points[(9*len(points))//10]


def _add_uptime(status):
    uptime = int(time.time() - status['stats']['start-ts'])
    uptimes = _history(status, 'uptime_s')
    if uptimes and uptime > uptimes[0]:
        uptimes.pop(0)
    _add_history(status, 'uptime_s', uptime)


def _save_server_stats(workdir, status):
    server = status['server']
    server_path = os.path.join(workdir, server)
    if not os.path.isdir(server_path):
        os.mkdir(server_path, 0o755)
    with open(os.path.join(server_path, 'status.json'), 'w') as fd:
        json.dump(status, fd, indent=1)
    sys.stderr.write('Update(%s): saved\n' % (server))


def _bail_out(error=None):
    print('%s\n' % __doc__.strip())
    if imapclient is None:
        print('WARNING: imapclient not found: Please pip3 install imapclient.')
    if error:
        print('ERROR:   %s' % error)
    sys.exit(1 if error else 0)


def op_stats(workdir, servers):
    if not servers:
        _bail_out('Need at least one server name')
    errors = 0
    for server in servers:
        url = 'https://%s/passcrow/stats' % server
        try:
            t0 = time.time()
            stats = json.load(urllib.request.urlopen(url, timeout=10))
            t1 = time.time()
            server_stats = _load_server_stats(workdir, server)
            server_stats.update({
                'stats_updated': int(time.time()),
                'stats': stats})
            _add_history(server_stats, 'stats_ms', int((t1 - t0) * 1000))
            _add_uptime(server_stats)
            sys.stderr.write('Update(%s): fetched\n' % (server,))
            _save_server_stats(workdir, server_stats)
        except Exception as e:
            sys.stderr.write('Update(%s): failed, %s\n' % (server, e))
            errors += 1
    return (errors == 0)


def op_etest(workdir, args):
    try:
        server, ttl, email = args
        ttl = int(ttl)
        if not (0 < ttl < 36500):
            raise ValueError('TTL is weird')
    except Exception as e:
        traceback.print_exc()
        _bail_out('Need a server, time-to-live in days and e-mail address.')

    server_stats = _load_server_stats(workdir, server)
    if 'escrows' not in server_stats:
        server_stats['escrows'] = {}
    escrows = server_stats['escrows']

    ekey = '%dD' % ttl
    if ekey in escrows:
        expiration = escrows[ekey].get('expires')
        if time.time() < expiration:
            sys.stderr.write('ETest(%s/%s): no update\n' % (server, ekey))
            return True
    else:
        escrows[ekey] = {}

    loglines = []
    def logger(msg):
        loglines.append(msg)
    try:
        data = '%x' % random.randint(0, 0xffffffff)
        client_path = os.path.join(workdir, server, 'client')
        client = PasscrowClient(
            default_expiration_days=ttl,
            config_dir=client_path,
            data_dir=client_path,
            create_dirs=True,
            env_override=False,
            logging_func=logger)
        policy = PasscrowRecoveryPolicy(
            idps=['email:%s via %s' % (email, server)],
            defaults=client.default_policy)

        if not client.protect(data, data, policy, quick=True):
            raise Exception('Failed')

        escrows[ekey]['protect_ok'] = 1 + escrows[ekey].get('protect_ok', 0)
        escrows[ekey].update({
            'expires': int(time.time() + (ttl*24*3600)),
            'secret': data})

        sys.stderr.write('ETest(%s/%s): updated\n' % (server, ekey))
        return True
    except Exception as e:
        escrows[ekey]['protect_fail'] = 1+escrows[ekey].get('protect_fail', 0)
        sys.stderr.write(''.join(loglines))
        sys.stderr.write('ETest(%s/%s): protect() failed\n' % (server, ekey))
    finally:
        _save_server_stats(workdir, server_stats)


def _run(ops, workdir, args):
    op = ops.get(args.pop(0).lower())
    if not op:
        _bail_out('Unknown operation: %s' % op)
    return op(workdir, args)


def op_auto(workdir, args):
    servers = _load_server_list(workdir)
    ops = {
        'stats': op_stats,
        'etest': op_etest}

    res = []
    def runner(op_args):
        res.append(_run(ops, workdir, op_args))

    jobs = []
    for server in servers:
        op_args = args[:1] + [server] + args[1:]
        jobs.append(threading.Thread(target=runner, args=(op_args,)))
        jobs[-1].start()
    for job in jobs:
        job.join()

    return False if (False in res) else True


def op_summarize(workdir, args):
    target = args.pop(0) if args else '-'
    servers = _load_server_list(workdir)
    for server in servers:
        try:
            server_stats = _load_server_stats(workdir, server)
            if not server_stats.get('stats', {}).get('handlers'):
                continue
            server_history = server_stats['history']

            uptime_days = time.time() - server_stats['stats']['start-ts']
            uptime_days = uptime_days // (24*36)
            uptime_days /= 100

            handlers = server_stats['stats']['handlers']
            if 'mailto' in handlers:
                handlers.remove('mailto')
            policy_line = '%s via %s' % (', '.join(sorted(handlers)), server)

            servers[server].update({
                'policy': policy_line,
                'version': server_stats['stats'].get('version', 'unknown'),
                'storage': server_stats['stats'].get('storage', {
                     'type': 'unknown',
                     'encrypted': False}),
                'handlers': handlers,
                'metrics': {'uptime_days': uptime_days}})
            for hist in (
                    'uptime_s_avg', 'uptime_s_m50', 'uptime_s_m90',
                    'stats_ms_avg', 'stats_ms_m50', 'stats_ms_m90'):
                if hist in server_history:
                    servers[server]['metrics'][hist] = server_history[hist]
        except:
            traceback.print_exc()
            pass
 
    if target == '-':
        print(json.dumps(servers, indent=2))
    else:
        with open(target, 'w') as fd:
            fd.write(json.dumps(servers, indent=2))
    return True


if __name__ == '__main__':
    args = sys.argv[1:]
    if len(args) < 2:
        _bail_out('Need a working directory and operation.')

    workdir = args.pop(0)
    if not os.path.isdir(workdir):
        _bail_out('Not a directory %s' % workdir)

    ops = {
        'auto': op_auto,
        'summarize': op_summarize,
        'stats': op_stats,
        'etest': op_etest}
    try:
        sys.exit(0 if _run(ops, workdir, args) else 2)
    except Exception as e:
        _bail_out(e)
