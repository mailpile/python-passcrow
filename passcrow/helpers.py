import base64
import json
import os

from .aes_utils import aes_ctr_encrypt, aes_ctr_decrypt


def _json_list(elem_type):
    class _jl(list):
        def __init__(self, other):
            super().__init__()
            self.extend(other)
        def __setitem__(self, key, value, **kwargs):
            return super().__setitem__(key, elem_type(value), **kwargs)
        def append(self, value):
            return super().append(elem_type(value))
        def extend(self, other):
            return super().extend((elem_type(v) for v in other))
    return _jl


class _json_object(dict):
    KEYS = {}

    class _json_encoder(json.JSONEncoder):
        def encode(self, o):
            if hasattr(o, '__json__'):
                return o.__json__()
            return super().encode(o)

    def __init__(self, *args, **kwargs):
        super().__init__()
        if not args and not kwargs:
            self._set_defaults()
        for a in args:
            self.update(a)
        self.update(kwargs)

    def _set_defaults(self):
        pass

    def update(self, other):
        for k, v in other.items():
            self[k.replace('_', '-')] = v
        return self

    def __setitem__(self, key, value, **kwargs):
        if key not in self.KEYS:
            raise KeyError("Invalid key: %s" % key)
        return super().__setitem__(key, self.KEYS[key](value), **kwargs)

    def __str__(self):
        return json.dumps(self, indent=2, cls=self._json_encoder)


class _encrypted_json_object(_json_object): 
    def __init__(self, *args, **kwargs):
        self.encrypted_data = None
        self.encryption_key = None
        if len(args) == 1 and isinstance(args[0], str):
            self.encrypted_data = args[0]
            super().__init__(self, **kwargs)
        else:
            super().__init__(self, *args, **kwargs)

    def encrypt(self, key):
        iv = os.urandom(16)
        ed = bytes(str(self), 'utf-8')
        ed = aes_ctr_encrypt(key, iv, ed)
        self.encryption_key = str(base64.b64encode(key), 'utf-8')
        self.encrypted_data = str(base64.b64encode(iv+ed), 'utf-8')
        return self

    def decrypt(self, key):
        ed = base64.b64decode(self.encrypted_data)
        ed = aes_ctr_decrypt(key, ed[:16], ed[16:])
        self.update(json.loads(ed))
        self.encrypted_data = None
        self.encryption_key = None
        return self

    def __str__(self):
        if self.encrypted_data is not None:
            return self.encrypted_data
        return super().__str__()
