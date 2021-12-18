import io
import json
import sys
import tempfile
import time

from .server import PasscrowServer, FileSystemStorage
from .handlers.email import make_email_hint


MOCK_SERVER = None


class MockHandler:
    def __init__(self):
        pass

    def send_code(server, email, description, vcode, timeout_seconds):
        print('%s <= (%s, %s, %d)' % (email, description, vcode, timeout_seconds))
        return make_email_hint(email)


def mock_warnings_to(address, expiration):
    print('Should warn %s about service interruptions, until %d'
        % (address, expiration))


def sleep_func(sleeptime):
    time.sleep(1)


def prepare_mock_server(data_dir):
    global MOCK_SERVER
    if not data_dir:
        data_dir = tempfile.mkdtemp(suffix=b'.passcrow')
    mock_handler = MockHandler()
    MOCK_SERVER = PasscrowServer(
        FileSystemStorage(data_dir, create=True),
        handlers={
            'mailto': mock_handler,
            'tel': mock_handler,
            'sms': mock_handler},
        warnings_to=mock_warnings_to)


def urlopen_func(url, data=None, **kwargs):
    global MOCK_SERVER
    rpc_method = url.rstrip('/').split('/')[-1]

    sys.stderr.write('%s <- %s\n' % (url, str(data, 'utf-8')))
    result = str(MOCK_SERVER.handle('mock', rpc_method, data))
    sys.stderr.write('%s -> %s\n' % (url, result))

    return io.StringIO(result)
