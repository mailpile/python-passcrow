import re

from ..proto import register_identity_kind


def validate_tel_identity(pnr):
    if not re.match(r'^\+?(\d+[- ]?)+\d\d+$', pnr.split(':', 1)[1]):
        raise ValueError('Phone numbers should be digits, dashes and spaces')
    # FIXME: Validate more?
    return pnr


register_identity_kind('tel', validate_tel_identity, 'SMS or a phone call to')
register_identity_kind('sms', validate_tel_identity, 'SMS to')
