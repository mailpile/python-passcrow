from flask import Response, request


def route_passcrow_api(app, server):
    server.log = lambda msg: app.logger.info('%s', msg)

    def user_info():
        info = {'remote_ip': request.remote_addr}
        if request.remote_user:
            info['user'] = request.remote_user
        return ', '.join('%s=%s' % (k, v) for k, v in info.items())

    def passcrow_policy():
        return Response(
            str(server.handle(user_info(), 'policy', request.data or '{}')),
            content_type="application/json")

    def passcrow_api(rpc_method):
        return Response(
            str(server.handle(user_info(), rpc_method, request.data)),
            content_type="application/json")

    app.route('/passcrow/policy', methods=['GET', 'POST'])(passcrow_policy)
    app.route('/passcrow/<rpc_method>', methods=['POST'])(passcrow_api)
