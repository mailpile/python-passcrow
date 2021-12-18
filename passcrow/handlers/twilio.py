from .tel import *

# FIXME

class TwilioSmsHandler:
    def __init__(self, api_key=None):
        self.api_key = api_key

    def send_code(self, *args):
        raise ValueError('FIXME: TwilioSmsHandler.send_code(...)')
