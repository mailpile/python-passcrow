import json
import urllib.request
import urllib.parse

from base64 import b64encode

from ..messages import VERIFICATION_BODY_SHORT
from .tel import *


def make_tel_hint(tel):
    # When the country code is >2 digits, we shift the starred out
    # section a bit further back in the number.
    if tel[:3] in ('+21', '+22', '+23', '+24', '+25', '+26', '+27', '+29',
                   '+35', '+37', '+38', '+42', '+50', '+59',
                   '+67', '+68', '+69', '+80', '+85', '+87', '+88',
                   '+96', '+97', '+99'):
        l1 = len(tel)//2 + 1
        l2 = -1
    else:
        l1 = len(tel)//3
        l2 = -2
    return '%s%s%s' % (tel[:l1], '*' * (len(tel)-l1+l2), tel[l2:])


class TwilioSmsHandler:
    DEF_API_SMS_URL = (
        'https://api.twilio.com/2010-04-01/Accounts/%(api_sid)s/Messages.json')

    def __init__(self,
            from_number=None,
            from_service=None,
            api_sid=None,
            api_token=None,
            msg_fmts=None,
            api_sms_url=None):
        self.from_number = from_number
        self.from_service = from_service
        self.api_token = api_token
        self.api_sid = api_sid

        self.api_sms_url = api_sms_url or self.DEF_API_SMS_URL
        self.msg_fmts = msg_fmts or VERIFICATION_BODY_SHORT

        self.params = {
            'api_sid': api_sid,
            'api_token': api_token}

        self.basic_auth = str(b64encode(
                bytes('%s:%s' % (api_sid, api_token), 'us-ascii'),
            ).strip(), 'us-ascii')

    def send_code(self, server, lang, tel, description, vcode, tmo_seconds):
        telnr = validate_tel_identity(tel).split(':', 1)[-1]
        post_url = self.api_sms_url % self.params
        post_data = {
            'To': telnr,
            'Body': (self.msg_fmts.get(lang, self.msg_fmts['en']) % {
                    'vcode': vcode,
                    'description': description,
                    'timeout_seconds': tmo_seconds,
                    'timeout_minutes': (tmo_seconds // 60)}
                ).strip()}
        if self.from_number:
            post_data['From'] = self.from_number
        if self.from_service:
            post_data['MessagingServiceSid'] = self.from_service

        post_data = bytes(urllib.parse.urlencode(post_data), 'us-ascii')
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic %s' % self.basic_auth}

        # Throws exceptions if this fails, which is good 'nuff.
        urllib.request.urlopen(
            urllib.request.Request(post_url,
                method='POST', data=post_data, headers=headers)).read()

        return make_tel_hint(telnr)
