import datetime
import base64
import json
import re
import sys
import time

from . import VERSION
from .util import arg_dict, cute_str


CLI_COMMANDS = {}


class UsageError(Exception):
    pass


def make_policy(args, pc=None, optional=False):
    """
    Policy options:
        -p <POLICY>   A verification policy (may be repeated)
        -r <N>[/<M>]  Require n-of-m identities for verification. If m
                      is omitted, the number of policies is used.
        -d <DAYS>     Request expiration after this many days
        -m <MINUTES>  Request verification timeouts of this many minutes
        -I            Ignore any default settings
    """
    from .client import PasscrowIdentityPolicy, PasscrowClientPolicy

    defaults = not args.get('-I')
    exp_days = int(args.get('-d', [0])[0]) or None
    tmo_mins = int(args.get('-m', [0])[0]) or None
    ratio = args.get('-r', [None])[0]
    idps = args.get('-p', [])
    if args['_']:
        if 'via' in args['_']:
            idps.append(' '.join(args['_']))
        else:
            idps.extend(args['_'])

    defp = pc.default_policy if (pc and defaults) else None
    if len(idps) < 1 and defp:
        idps = [str(idp) for idp in defp.idps]

    try:
        idps = [PasscrowIdentityPolicy().parse(i, defaults=defp) for i in idps]
    except ValueError as e:
        raise UsageError('Bad policy: %s' % e)

    if not optional:
        for pip in idps:
            if not pip.server:
                raise UsageError('No server found for: %s' % pip)
            if not pip.usable:
                raise UsageError('Policy is incomplete: %s' % pip)
        if len(idps) < 1:
            raise UsageError('At least one policy is required.')

    if ratio:
        try:
            n, m = (int(i) for i in ratio.split('/'))
        except:
            n = int(ratio)
            m = len(idps)
    elif defp:
        n, m = defp.n, defp.m
    elif not optional:
        raise UsageError('Please specify a ratio.')
    else:
        n = m = None

    return PasscrowClientPolicy(idps=idps, n=n, m=m,
        expiration_days=exp_days,
        timeout_minutes=tmo_mins)


def make_pc(args, create_dirs=False):
    """
    Global options:
        -C <path>  Set PASSCROW_CONFIG, the directory for configuration
        -D <path>  Set PASSCROW_DATA, the directory for data
        -H <path>  Set PASSCROW_HOME, a shared directory for config and data
        -T         Local Testing mode: use internal mock server

    Note: PASSCROW_HOME, PASSCROW_CONFIG, and PASSCROW_DATA may also be
          configured using environment variables of the same name.
    """
    pc_home = args.get('-H', [None])[0]
    pc_data = args.get('-D', [None])[0]
    pc_conf = args.get('-C', [None])[0]
    pc_test = args.get('-T', False)
    if pc_home and (pc_data or pc_conf):
        raise UsageError(
            'Please use option -H or -C/-D (or neither), but not both.')
    try:
        from .client import PasscrowClient
        if pc_test:
            from .mock import prepare_mock_server, sleep_func, urlopen_func
        else:
            sleep_func = urlopen_func = None
        pc = PasscrowClient(
            config_dir=pc_conf or pc_home,
            data_dir=pc_data or pc_home,
            env_override=(not (pc_home or pc_data or pc_conf)),
            create_dirs=create_dirs,
            sleep_func=sleep_func,
            urlopen_func=urlopen_func)
        if pc_test:
            prepare_mock_server(pc.data_dir)
        return pc
    except (OSError, IOError) as e:
        raise UsageError(e)


def cli_init(args):
    """[...]

    Initialize the passcrow recovery database and create a default
    configuration file.

    After running this command, the user may edit the configuration
    file to configure a default policy (identities and passcrow servers).
    """
    args = arg_dict(args, options='C:D:H:T', invalid_exc=UsageError)

    # Create our passcrow object and directories
    pc = make_pc(args, create_dirs=True)

    # Enable the test server by default
    pc.default_policy.servers = ['mailto via passcrow-test.mailpile.is']
    sys.stderr.write("""\
NOTE: Configuring `passcrow-test.mailpile.is` as the default server for
      e-mail (mailto) verification. Note that this server is for testing
      only and deletes all data after 30 days, no matter what expiration
      has been requested/promised.\n\n""")

    saved = pc.save_default_policy()
    sys.stderr.write(
        'Edit your default Passcrow policy here: %s\n' % cute_str(saved))

    return True


def cli_list(args):
    """[...]

    Display an overview of the current passcrow recovery database contents.

    Options:
        -b            Batch mode, generates machine-readable output

    Batch mode will output a tab-delimited list containing the same data
    and columns as the human-friendly version.
    """
    # FIXME: Allow arguments to tweak the sort order, time format, etc.
    args = arg_dict(args, options='C:D:H:Tb', invalid_exc=UsageError)
    batch = args.get('-b', False)
    try:
        secrets = list(make_pc(args))
        if secrets:
            # Sort our output
            secrets.sort(key=lambda p: (p[1].created_ts, p[0]))

            if batch:
              fmt = '%s\t%s\t%s\t%s\t%s'
            else:
              fmt = '%-10.10s%6.6s  %-10.10s%6.6s  %s'
              print(fmt % ('CREATED', '', 'EXPIRES', '', 'NAME'))

            for name, pack in secrets:
                ct = pack.created
                et = pack.expires
                print(fmt % (
                    '%4.4d-%2.2d-%2.2d' % (ct.year, ct.month, ct.day),
                    '%2.2d:%2.2d' % (ct.hour, ct.minute),
                    '%4.4d-%2.2d-%2.2d' % (et.year, et.month, et.day),
                    '%2.2d:%2.2d' % (et.hour, et.minute),
                    name))
        else:
            sys.stderr.write('*** (no passcrow data) ***\n')

    except KeyboardInterrupt:
        pass
    except Exception as e:
        sys.stderr.write('Failed list(...): %s\n' % e)
        return False
    return True


def cli_protect(args):
    """[<PATH|->] [<POLICY>] [...]

    Add a new secret to the passcrow recovery database and send Escrow
    Requests to one or more passcrow servers, so the data can be recovered
    later. The protected data can either be read from standard input (-)
    or loaded from a file.

    If policy details are incomplete (no ratios, missing server details),
    the defaults set during `passcrow init` will be used.

    Examples:
        passcrow protect secrets.txt  # Use the default policy

        passcrow protect special-secret.txt -r 1/2 a@a.org b@b.org

        cat secrets.txt | passcrow protect -n "My Secret Data"

    Options:
        -b            Batch mode, generates machine-readable output
        -n <NAME>     Description in passcrow database (required for stdin)
        -e            Ephemeral: local storage optional, small secrets only
        -E            Ephemeral only: skip local storage, small secrets only
    """
    # FIXME: -q       Quick operation (reduced anonymity)
    # FIXME: -f = force, otherwise refuse to clobber existing secrets?

    args = arg_dict(args,
        options='C:D:H:TIp:r:d:m:beEn:q',
        multi='np',
        bare_args=True,
        invalid_exc=UsageError)
    if not args['_']:
        args['_'].append('-')

    from .client import EPHEMERAL_ONLY, EPHEMERAL_BOTH
    ephemeral = args.get('-e', False) and EPHEMERAL_BOTH
    if not ephemeral:
        ephemeral = args.get('-E', False) and EPHEMERAL_ONLY

    quick = args.get('-q', False) or True  # FIXME
    batch = args.get('-b', False)
    source = args['_'].pop(0)
    try:
        name = ' '.join(args['-n'])
    except KeyError:
        if source == '-':
            if ephemeral == EPHEMERAL_ONLY:
                name = 'Data'
            else:
                raise UsageError('Please provide a name (-n).')
        else:
            name = source

    try:
        source = sys.stdin.buffer if (source == '-') else open(source, 'rb')
        pc = make_pc(args)
        pol = make_policy(args, pc)
        data = source.read()
    except (IOError, OSError) as e:
        raise UsageError(e)

    try:
        result = pc.protect(name, data, pol, quick=quick, ephemeral=ephemeral)
        if ephemeral and result:
            if batch:
                print('%s' % result)
            else:
                ed = datetime.datetime.fromtimestamp(result.response.expiration)
                print("""\
Your data has been placed in ephemeral escrow.

This means recovery can be initiated without any local data, using the
following command. Write down or print this out, keep it safe!

    passcrow recover %s:%s

You may prefer to record/print this URL, which generates instructions:

    https://%s/recover/#%s

The data will expire from escrow on %4.4d-%2.2d-%2.2d.""" % (
                    result.server,
                    result.recovery_key,
                    result.server,
                    result.recovery_key,
                    ed.year, ed.month, ed.day))
            return True
        return result
    except KeyboardInterrupt:
        pass
    except Exception as e:
        sys.stderr.write('Failed protect(...): %s\n' % e)
    return False


def cli_recover(args):
    """<SECRET_NAME> [<VERIFICATION_CODES>]

    Recover one of your passcrow-protected secrets.

    If verification codes are not provided, the servers will be prompted
    to initiate verification and you will need to re-run the command once
    you have received the necessary codes. Ephemeral recovery requires
    two rounds of verification (three invocations in total).

    Example:
        passcrow recover "Secret 1"
        passcrow recover "Secret 1" A-123423 B-999888 C-333444

    Ephemeral example:
        passcrow recover passcrow.example.org:AbCd-1234-FfIi-Xyz0
        passcrow recover AbCd-1234-FfIi-Xyz0 A-123123
        passcrow recover AbCd-1234-FfIi-Xyz0 A-654321 B-123123 C-...

    Options:
        -o <FILENAME> Write recovered data to file (default is stdout)
        -b            Batch mode, generates machine-readable output

    Batch mode will always output a JSON object describing the recovery
    progress. Recovered data, if present, is base64 encoded.
    """
    args = arg_dict(args, options='C:D:H:To:bq', bare_args=True,
                          invalid_exc=UsageError)
    if not args['_']:
        raise UsageError('Recover what?')

    # FIXME: -o does not work

    quick = args.get('-q', False) or True  # FIXME
    batch = args.get('-b', False)
    name = args['_'].pop(0)
    codes = args['_']
    try:
        pc = make_pc(args)
        pack = pc.pack(name)
    except (KeyError, OSError) as e:
        raise UsageError(e)

    if codes and len(codes) < pack.min_shares:
        raise UsageError('Need at least %d verification codes'
            % (pack.min_shares))

    try:
        if codes:
            secret_data = pc.recover(pack, codes, quick=quick)
            if not secret_data:
                raise Exception('Sorry')

            if 'is-ephemeral' in pack and pack.is_ephemeral:
                pack = secret_data  # Switcheroo!

            else:
                if batch:
                    print(json.dumps({
                        "name": name,
                        "data": str(base64.b64encode(secret_data), 'latin-1'),
                        "recovered": True}, indent=2))
                else:
                    sys.stdout.write(str(secret_data, 'latin-1'))
                return True

        vfys = pc.verify(pack, quick=quick)
        if vfys:
            timeout = min(v.expiration for v in vfys) - int(time.time())
            hints = [v.get_hints() for v in vfys]
            if batch:
                print(json.dumps({
                    "name": name,
                    "min-shares": pack.min_shares,
                    "timeout": timeout,
                    "verifications": hints,
                    "recovered": False}, indent=2))
            else:
                url_list = ['    * %(url)s (login hint: %(hint)s)' % hint
                    for hint in hints if 'action-url' in hint]
                if url_list:
                    url_list = (
                        'You can find verification codes at URLs:\n%s\n'
                        % '\n'.join(sorted(url_list)))
                else:
                    url_list = ''

                hint_list = ['    * %(kind)s: %(hint)s' % hint
                    for hint in hints if 'action-url' not in hint]
                if hint_list:
                    hint_list = (
                        'You should receive %d verification code(s):\n%s\n'
                        % (len(hint_list), '\n'.join(sorted(hint_list))))
                else:
                    hint_list = ''

                print("""\
Verification initiated!

%s%s\

When you have received the codes, please re-run `passcrow recover`
with the codes as arguments. For example:

    passcrow recover "%s" %s

You must provide at least %d code(s) within %d minutes.""" % (
                    hint_list, url_list,
                    pack.name,
                    ' '.join(['A-123456', 'B-321123'][:pack.min_shares]),
                    pack.min_shares,
                    round(timeout/60)))
        return True
    except KeyboardInterrupt:
        pass
    except Exception as e:
        import traceback
        traceback.print_exc()
        sys.stderr.write('Failed recover(%s): %s\n' % (name, e))
    return False


def cli_forget(args):
    """<SECRET_NAMES>

    Delete one or more secrets from your passcrow recovery database.
    Data will be deleted from the passcrow servers as well.

    Examples:
        passcrow forget "Secret 1" "Secret 2"

    Options:
        -l            Local only (do not contact remote servers)
    """
    args = arg_dict(args, options='C:D:H:Tlq', bare_args=True,
                          invalid_exc=UsageError)

    names = args['_']
    quick = args.get('-q', False) or True  # FIXME
    noremote = args.get('-l', False)
    pc = make_pc(args)

    # FIXME: Add support for ephemeral forgetfulness? Do we want to be
    #        thorough, which would imply a partial recovery of the pack
    #        itself, or just delete the pack and trust that is enough?

    failed = []
    for name in names:
        try:
            if not pc.delete(name, remote=(not noremote), quick=quick):
                raise ValueError('delete failed')
        except (ValueError, OSError) as e:
            sys.stderr.write('Failed(%s): %s\n' % (name, e))
            failed.append(name)
    return (not failed)


def cli_server_init(args):
    """[<USER> [<CONFIG_FILE> [<DATA_DIRECTORY>]]]

    Create a default passcrow server configuration file and data directory.

    The user (default name: passcrow) must exist and the command must be
    run with sufficient permissions to create the configuration file, data
    directory and set permissions of the latter.
    """
    from .server import PasscrowServer
    opts = arg_dict(args, options='f', bare_args=True, invalid_exc=UsageError)
    args = opts['_']

    # Create our passcrow object and directories
    force    = opts.get('-f', False)
    user     = args[0] if (len(args) > 0) else 'passcrow'
    config   = args[1] if (len(args) > 1) else '/etc/passcrow/server_config.py'
    data_dir = args[2] if (len(args) > 2) else '/var/spool/passcrow'

    try:
        sys.stderr.write(
            'Edit your Passcrow Server settings here: %s\n' %
            cute_str(PasscrowServer.Init(user, config, data_dir, force=force)))
    except (OSError, KeyError, IndexError, ValueError) as e:
        raise UsageError(e)

    return True


def cli_help(args, error=None):
    """
    This is python-passcrow version @VERSION@.

    Passcrow is a tool to facilitate secure password/passphrase/key
    recovery when using local encryption.

    For each recoverable data set, passcrow creates an AES encrypted
    "recovery pack" which can only be decrypted with the help of one
    or more remote passcrow servers, which in turn take care of
    verifying the identity of the owner before providing assistance.

    By default recovery packs are only stored locally. However, in
    "ephemeral mode", an encrypted copy of the recovery pack itself will
    be uploaded to a passcrow server to facilitate recovery if a device
    is lost, or to recover access to the device itself.

    Before using the passcrow tool, you must initialize your local
    recovery database by running `passcrow init` and editing the
    configuration file it generates.

    Run `passcrow help COMMAND` for more details about each command.
"""
    if error:
        p = lambda t: sys.stderr.write('%s\n' % t)
    else:
        p = print
    if args and args[0] in CLI_COMMANDS:
        cmd = CLI_COMMANDS[args[0]]
        p('passcrow %s %s' % (args[0], cmd.__doc__.rstrip()))
        if cmd == cli_init:
            p(make_pc.__doc__.rstrip())
        if cmd == cli_protect:
            from .client import PasscrowIdentityPolicy
            p(make_policy.__doc__.rstrip())
            p(PasscrowIdentityPolicy.__doc__.rstrip())
        if error is not None:
            p('\nError: %s' % error)
        else:
            p()
        return True
    else:
        p('passcrow [%s]' % '|'.join(sorted(CLI_COMMANDS.keys())))
        p(cli_help.__doc__)
        if error is not None:
            p('Error: %s' % error)
        return (not args)


def cli_main(args):
    try:
        return CLI_COMMANDS[args[0]](args[1:])
    except KeyboardInterrupt:
        print('(Aborted)')
        return False
    except UsageError as e:
        cli_help(args[:1], error=str(e))
    except (IndexError, KeyError):
        cli_help(args, error='Need a valid command to continue')
    return False


cli_help.__doc__ = cli_help.__doc__.replace('@VERSION@', VERSION)

CLI_COMMANDS.update({
    'server_init': cli_server_init,
    'init': cli_init,
    'list': cli_list,
    'protect': cli_protect,
    'recover': cli_recover,
    'forget': cli_forget,
    'help': cli_help})


def main():
    sys.exit(0 if cli_main(sys.argv[1:]) else 1)


if __name__ == '__main__':
    main()
