from upagekite import uPageKite, LocalHTTPKite
from upagekite.httpd import HTTPD, url
from upagekite.proto import uPageKiteDefaults, Kite
from upagekite.web import process_post


global PC_SERVER


def user_info(req_env):
    info = {'remote_ip': req_env.remote_ip}
    return ', '.join('%s=%s' % (k, v) for k, v in info.items())


def passcrow_api(req_env):
    rpc_method = req_env.request_path.rsplit('/', 1)[-1]
    if rpc_method != 'policy' and req_env.http_method != 'POST':
        return {'code': 400, 'msg': 'Forbidden', 'body': 'Forbidden'}

    resp = PC_SERVER.handle(user_info(req_env), rpc_method, req_env.post_data)
    return {
        'mimetype': "application/json",
        'body': str(resp)}


def run_server(server, kite_name, kite_secret):
    global PC_SERVER
    PC_SERVER = server

    class pcPageKiteSettings(uPageKiteDefaults):
        info = server.log
        error = server.log
        debug = server.log

    uPK = pcPageKiteSettings 
    env = {}
    httpd = HTTPD(kite_name, '/unused', env, uPK)
    socks = []
    if ':' in kite_name:
        port, kite_name = kite_name.split(':', 1)
        kite = LocalHTTPKite(
            int(port), kite_name, kite_secret,
            handler=httpd.handle_http_request)
        socks.append(kite)
    else:
        kite = Kite(kite_name, kite_secret, handler=httpd.handle_http_request)

    # Programmatically configure our handlers instead of using decorators,
    # so the max_request_bytes matches our server configuration.
    url(*['/passcrow/%s' % m for m in server.endpoints])(
        process_post(max_bytes=server.max_request_bytes)(
            passcrow_api))

    uPageKite([kite], socks=socks, uPK=uPK).run()


if __name__ == '__main__':
   import sys
   from ..server import PasscrowServer

   try:
       kite_name = sys.argv[1]
       kite_secret = sys.argv[2]
   except IndexError:
       sys.stderr.write(
           'Usage: \tpython3 -m pagekite.integration.upagekite_app \\\n'
           '\t\t<[port:]kite_name> <kite_secret> <path/to/config>\n')
       sys.exit(1)

   pcs = PasscrowServer.FromConfig(sys.argv[3:])
   if not pcs:
       sys.exit(2)

   run_server(pcs, kite_name, kite_secret)
