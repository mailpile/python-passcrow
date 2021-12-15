import json
import base64

from .helpers import _json_list, _json_object, _encrypted_json_object


PASSCROW_PROTO_VERSION = "1.0"


class Identity(str):
    def __new__(self, other):
        if '@' not in other:
            raise ValueError('Invalid identity: %s' % other)
        return super().__new__(self, other)


class PolicyObject(_json_object):
    pass


class EscrowRequestParameters(_encrypted_json_object):
    KEYS = {
        "expiration": int,
        "warnings-to": str,
        "methods": _json_list(str),
        "payment": _json_list(str)}


class EscrowRequestDataIdentities(_json_object):
    KEYS = {
        "required": _json_list(Identity),
        "any-1": _json_list(Identity),
        "any-2": _json_list(Identity),
        "any-3": _json_list(Identity),
        "any-4": _json_list(Identity),
        "any-5": _json_list(Identity),
        "any-6": _json_list(Identity)}


class EscrowRequestData(_encrypted_json_object):
    KEYS = {
        "secret": str,
        "identities": EscrowRequestDataIdentities,
        "notify": _json_list(Identity)}



class EscrowRequest(_json_object):
    KEYS = {
        "passcrow-escrow-request": str,
        "parameters-key": str,
        "parameters": str,
        "escrow-data": str}

    def _set_defaults(self):
        self["passcrow-escrow-request"] = PASSCROW_PROTO_VERSION

    def parameters(self):
        erp = EscrowRequestParameters(self['parameters'])
        return erp.decrypt(base64.b64decode(self['parameters-key']))

    def data(self, key):
        erd = EscrowRequestData(self['escrow-data'])
        return erd.decrypt(key)


class EscrowResponse(_json_object):
    """
    """
    pass


class VerificationRequest(_json_object):
    """
    """
    KEYS = {
        "passcrow-verification-request": str,
        "parameters-key": str,
        "parameters": str,
        "escrow-data": str}

    def _set_defaults(self):
        self["passcrow-verification-request"] = PASSCROW_PROTO_VERSION


class VerificationResponse(_json_object):
    """
    """
    pass


class RecoveryRequest(_json_object):
    """
    """
    pass


class RecoveryResponse(_json_object):
    """
    """
    pass


class DeletionRequest(_json_object):
    """
    """
    pass


class DeletionResponse(_json_object):
    """
    """
    pass



if __name__ == "__main__":
    import time

    erd = EscrowRequestData({
        'notify': ['bre@klaki.net'],
        'identities': {'required': ['bre@klaki.net']}})
    erp = EscrowRequestParameters({
            'payment': ['1234'],
            'expiration': time.time() + 3600})

    print(EscrowRequest().update({
        'parameters-key': erp.encryption_key,
        'parameters': erp,
        'escrow-data': erd}))

    key = b'1234123412341234'
    erd.encrypt(key)
    erp.encrypt(key)
    er = EscrowRequest({
        'parameters-key': erp.encryption_key,
        'parameters': erp,
        'escrow-data': erd})
    print(er)

    er2 = EscrowRequest(json.loads(str(er)))
    print(er2.parameters())
    print(er2.data(key))
