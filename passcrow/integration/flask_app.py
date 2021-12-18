import logging
import os
import sys

from flask import Flask, redirect

from ..server import PasscrowServer
from .flask_common import route_passcrow_api


app = Flask('passcrow')
if "gunicorn" in os.environ.get("SERVER_SOFTWARE", ""):
    app.logger = logging.getLogger('gunicorn.error')

try:
    args_skip = 1 + sys.argv.index('passcrow.integration.flask_app:app')
except ValueError:
    args_skip = len(sys.argv)

server = PasscrowServer.FromConfig(sys.argv[args_skip:])
route_passcrow_api(app, server)


@app.route('/')
def passcrow_root():
    return redirect(server.about_url)
