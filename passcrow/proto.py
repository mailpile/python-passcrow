"""Passcrow Protocol data structures

All "on the wire" data structures are JSON objects, with the additional
constraint that the server places hard upper bounds on the allowed size
of each message.

These upper bounds are to conserve resources on the server side; the
server is blindly storing encrypted objects which it cannot validate
until the client provides a recovery key.

The Python implementions follow the convention that each field of the
JSON object is data descriptor on the equivalent object, where dashes
in the JSON name are represented as underscores in Python. The str()
representation of the Python objects is the JSON structure.
"""
import base64
import json
import re

from .aes_utils import random_aesgcm_key
from .util import _json_object, _encrypted_json_object
from .util import _json_list, _json_object_prop


PASSCROW_PROTO_VERSION = "1.0"
PASSCROW_SUPPORTED_VERS = ("1.0",)

PASSCROW_ABOUT_URL = 'https://passcrow.mailpile.is/'

EXPLAIN_KINDS = {}


class Identity(str):
    """
    An Identity is a string of the form `kind:address` (such as
    `mailto:bre@example.org` or `tel:+3545885522`), to which a recovery
    code can be sent. The address part is an e-mail address, a
    telephone number, or some verifiable identity.

    Examples of `kind` values include:

        mailto: for e-mail addresses
        tel: telephone numbers (server decides how to contact)
        sms: telephone numbers using SMS-based verification
        signal: telephone numbers over Signal

    The passcrow server will report which Identity kinds they support
    in their PolicyObject.
    """
    _KINDS = {}

    @classmethod
    def _validate(self, value):
        kind, addr = value.split(':', 1)
        if kind not in self._KINDS:
            raise ValueError('Unsupported identity scheme: %s' % kind)
        return self._KINDS[kind](value)

    kind = property(lambda s: s.split(':', 1)[0])
    address = property(lambda s: s.split(':', 1)[1])

    def __new__(self, other):
        if ':' not in other:
            if '@' in other:
                other = 'mailto:' + other
            elif re.match(r'^\+?(\d+[- ]?)+\d\d+$', other):
                other = 'tel:' + other
        if ':' not in other:
            raise ValueError('Invalid identity: %s' % other)
        return super().__new__(self, Identity._validate(other))


def register_identity_kind(kind, validator, explain):
    global EXPLAIN_KINDS
    Identity._KINDS[kind] = validator
    EXPLAIN_KINDS[kind] = explain


class EscrowRequestParameters(_encrypted_json_object):
    """
    These are the parameters of an EscrowRequest. They are sent encrypted
    to the Passcrow Server along with a key, to immediately verify that
    the Server and passcrow client are using compatible encryption schemes.

    The `expiration` is a Unix timestamp (integer), describing how long
    the client owould like the server to keep the data around.

    The `kind` describes which kind of Identity the client wants
    verified, without revealing the actual identity. This allows the
    server to return an error if some Identities are unsupported.

    The `payment` is a  tokens (strings) which represents payment for the
    service requested.

    The `warnings_to` attribute is opional, if present listing a single
    Identity, which should be warned if the server is experiencing
    operational issues which may prevent recovery. This includes both
    serious server-side operational issues, and user-initiated deletion
    of escrowed data. This should be omitted for users who need strong
    anonymity guarantees.

    The `prefer_id` is optional and can be used to ask the escrow server
    to allocate a chosen ID to this data. The server may choose not to
    honor this request.
    """
    _KEYS = {
        "kind": str,
        "expiration": int,
        "warnings-to": Identity,
        "prefer-id": str,
        "payment": str}

    kind = property(*_json_object_prop('kind'))
    expiration = property(*_json_object_prop('expiration'))
    warnings_to = property(*_json_object_prop('warnings-to'))
    prefer_id = property(*_json_object_prop('prefer-id'))
    payment = property(*_json_object_prop('payment'))


class EscrowRequestData(_encrypted_json_object):
    """
    A class representing an identity verification rule (one Identity
    to verify, zero or one to notify, and a secret to relese), for use
    within an EscrowRequest. The description must be a very short hint
    about what verification is taking place.

    The timeout is the maximum time in seconds to allow verification
    to take before deleting the secret from RAM and failing by default.
    Note that servers may place their own upper bounds on this value
    for performance reasonss.
    """
    _KEYS = {
        "description": str,
        "secret": str,
        "verify": Identity,
        "timeout": int,
        "notify": Identity}

    description = property(*_json_object_prop('description'))
    verify = property(*_json_object_prop('verify'))
    notify = property(*_json_object_prop('notify'))
    timeout = property(*_json_object_prop('timeout'))
    secret = property(*_json_object_prop('secret'))


class EscrowRequest(_json_object):
    _KEYS = {
        "passcrow-escrow-request": str,
        "parameters-key": str,
        "parameters": str,
        "escrow-data": _json_list(str)}

    passcrow_escrow_request = property(*_json_object_prop('passcrow-escrow-request'))
    parameters_key = property(*_json_object_prop('parameters-key'))
    parameters = property(*_json_object_prop('parameters'))
    escrow_data = property(*_json_object_prop('escrow-data'))

    def _set_defaults(self):
        self.passcrow_escrow_request = PASSCROW_PROTO_VERSION

    def _check_self(self):
        if self.passcrow_escrow_request not in PASSCROW_SUPPORTED_VERS:
            raise ValueError('Unsupported request version')

    def get_parameters(self):
        """
        Decrypt paramters and return EscrowRequestParameters()
        """
        erp = EscrowRequestParameters(self.parameters)
        return erp.decrypt(base64.b64decode(self.parameters_key))

    def get_data(self, key):
        """
        Decrypt escrow data and return EscrowRequestData()
        """
        erd = [EscrowRequestData(d).decrypt(key) for d in self.escrow_data]
        return erd


class EscrowResponse(_json_object):
    """
    """
    _KEYS = {
        "passcrow-escrow-response": str,
        "escrow-data-id": str,
        "expiration": int,
        "error": str}

    passcrow_escrow_response = property(*_json_object_prop('passcrow-escrow-response'))
    escrow_data_id = property(*_json_object_prop('escrow-data-id'))
    expiration = property(*_json_object_prop('expiration'))
    error = property(*_json_object_prop('error'))

    def _set_defaults(self):
        self.passcrow_escrow_response = PASSCROW_PROTO_VERSION

    def _check_self(self):
        if self.passcrow_escrow_response not in PASSCROW_SUPPORTED_VERS:
            raise ValueError('Unsupported response version')


class VerificationRequest(_json_object):
    """
    """
    _KEYS = {
        "passcrow-verification-request": str,
        "escrow-data-id": str,
        "escrow-data-key": str,
        "prefix": str}

    passcrow_verification_request = property(*_json_object_prop('passcrow-verification-request'))
    escrow_data_id = property(*_json_object_prop('escrow-data-id'))
    escrow_data_key = property(*_json_object_prop('escrow-data-key'))
    prefix = property(*_json_object_prop('prefix'))

    def _set_defaults(self):
        self.passcrow_verification_request = PASSCROW_PROTO_VERSION

    def _check_self(self):
        if self.passcrow_verification_request not in PASSCROW_SUPPORTED_VERS:
            raise ValueError('Unsupported request version')



class VerificationResponse(_json_object):
    """
    """
    _KEYS = {
        "passcrow-verification-response": str,
        "hint": str,
        "action-url": str,
        "escrow-data-id": str,
        "expiration": int,
        "kind": str,       # Not used on the wire, internal only
        "prefix": str,     # Not used on the wire, internal only
        "error": str}

    passcrow_verification_response = property(*_json_object_prop('passcrow-verification-response'))
    hint = property(*_json_object_prop('hint'))
    action_url = property(*_json_object_prop('action-url'))
    escrow_data_id = property(*_json_object_prop('escrow-data-id'))
    expiration = property(*_json_object_prop('expiration'))
    kind = property(*_json_object_prop('kind'))
    prefix = property(*_json_object_prop('prefix'))
    error = property(*_json_object_prop('error'))

    def _set_defaults(self):
        self.passcrow_verification_response = PASSCROW_PROTO_VERSION

    def _check_self(self):
        if self.passcrow_verification_response not in PASSCROW_SUPPORTED_VERS:
            raise ValueError('Unsupported response version')

    def get_hints(self):
        hints = dict((k, v) for k, v in self._dict.items()
            if k in ('prefix', 'kind', 'expiration', 'hint', 'action-url'))
        hints['kind'] = EXPLAIN_KINDS.get(hints['kind'], hints['kind'])
        return hints


class RecoveryRequest(_json_object):
    """
    """
    _KEYS = {
        "passcrow-recovery-request": str,
        "escrow-data-id": str,
        "escrow-data-key": str,
        "verification": str}

    passcrow_recovery_request = property(*_json_object_prop('passcrow-recovery-request'))
    escrow_data_id = property(*_json_object_prop('escrow-data-id'))
    escrow_data_key = property(*_json_object_prop('escrow-data-key'))
    verification = property(*_json_object_prop('verification'))

    def _set_defaults(self):
        self.passcrow_recovery_request = PASSCROW_PROTO_VERSION

    def _check_self(self):
        if self.passcrow_recovery_request not in PASSCROW_SUPPORTED_VERS:
            raise ValueError('Unsupported request version')


class RecoveryResponse(_json_object):
    """
    """
    _KEYS = {
        "passcrow-recovery-response": str,
        "escrow-secret": str,
        "error": str}

    passcrow_recovery_response = property(*_json_object_prop('passcrow-recovery-response'))
    escrow_secret = property(*_json_object_prop('escrow-secret'))
    error = property(*_json_object_prop('error'))

    def _set_defaults(self):
        self.passcrow_recovery_response = PASSCROW_PROTO_VERSION

    def _check_self(self):
        if self.passcrow_recovery_response not in PASSCROW_SUPPORTED_VERS:
            raise ValueError('Unsupported response version')


class DeletionRequest(_json_object):
    """
    """
    _KEYS = {
        "passcrow-deletion-request": str,
        "escrow-data-id": str}

    passcrow_deletion_request = property(*_json_object_prop('passcrow-deletion-request'))
    escrow_data_id = property(*_json_object_prop('escrow-data-id'))

    def _set_defaults(self):
        self.passcrow_deletion_request = PASSCROW_PROTO_VERSION

    def _check_self(self):
        if self.passcrow_deletion_request not in PASSCROW_SUPPORTED_VERS:
            raise ValueError('Unsupported request version')


class DeletionResponse(_json_object):
    """
    """
    _KEYS = {
        "passcrow-deletion-response": str,
        "escrow-data-id": str,
        "error": str}

    passcrow_deletion_response = property(*_json_object_prop('passcrow-deletion-response'))
    escrow_data_id = property(*_json_object_prop('escrow-data-id'))
    error = property(*_json_object_prop('error'))

    def _set_defaults(self):
        self.passcrow_deletion_response = PASSCROW_PROTO_VERSION

    def _check_self(self):
        if self.passcrow_deletion_response not in PASSCROW_SUPPORTED_VERS:
            raise ValueError('Unsupported response version')


class PaymentScheme(_json_object):
    """
    This describes a passcrow server's payment scheme.
    """
    _KEYS = {
        "scheme": str,
        "scheme-id": str,
        "description": str,
        "expiration-seconds": int,
        "hashcash-bits": int,
        "tokens": _json_list(str)}

    scheme = property(*_json_object_prop('scheme'))
    scheme_id = property(*_json_object_prop('scheme-id'))
    description = property(*_json_object_prop('description'))
    expiration_seconds = property(*_json_object_prop('expiration-seconds'))
    hashcash_bits = property(*_json_object_prop('hashcash-bits'))
    tokens = property(*_json_object_prop('tokens'))


class PolicyObject(_json_object):
    """
    This describes a passcrow server's requirements and capabilities.
    """
    _KEYS = {
        "passcrow-versions": _json_list(str),
        "country-code": str,
        "about-url": str,
        "kinds": _json_list(str),
        "max-request-bytes": int,
        "max-expiration-seconds": int,
        "max-timeout-seconds": int,
        "payment-schemes": _json_list(PaymentScheme)}

    def _set_defaults(self):
        self.passcrow_versions = PASSCROW_SUPPORTED_VERS

    passcrow_versions = property(*_json_object_prop('passcrow-versions'))
    country_code = property(*_json_object_prop('country-code'))
    about_url = property(*_json_object_prop('about-url'))
    kinds = property(*_json_object_prop('kinds'))
    max_request_bytes = property(*_json_object_prop('max-request-bytes'))
    max_expiration_seconds = property(*_json_object_prop('max-expiration-seconds'))
    max_timeout_seconds = property(*_json_object_prop('max-timeout-seconds'))
    payment_schemes = property(*_json_object_prop('payment-schemes'))


if __name__ == "__main__":
    import time

    erd = EscrowRequestData().update({
        'description': 'Foo-wallet',
        'notify': 'mailto:bre@example.org',
        'verify': 'mailto:bre@example.org'})
    erp = EscrowRequestParameters()
    erp.payment = ['1234']
    erp.expiration = time.time() + 3600

    print(EscrowRequest().update(
        parameters_key=erp.encryption_key,
        parameters=erp,
        escrow_data=[erd]))

    erd_key = random_aesgcm_key()
    erp_key = random_aesgcm_key()
    erd.encrypt(erd_key)
    erp.encrypt(erp_key)
    er = EscrowRequest().update({
        'parameters-key': erp.encryption_key,
        'parameters': erp,
        'escrow-data': [erd]})
    print(er)

    er2 = EscrowRequest(json.loads(str(er)))
    print(er2.get_parameters())
    print(', '.join(str(d) for d in er2.get_data(erd_key)))
