import base64
import json
import os
import zlib

from .aes_utils import random_bytes, aesgcm_encrypt, aesgcm_decrypt


def arg_dict(args,
        invalid_exc=None,
        options='',
        multi='',
        bare_args=False):
    last, _dict = '_', {'_': []}
    options += '\n'
    for a in args:
        if a[:1] == '-' and len(a) > 1:
            try:
                oidx = options.index(a[1])
            except:
                if invalid_exc:
                    raise invalid_exc('Bad option: %s' % a)
            if invalid_exc and a[1:] not in multi and a in _dict:
                raise invalid_exc('Too many options: %s' % a)

            if oidx < len(options) and options[oidx+1] == ':':
                last = a
                _dict[last] = _dict.get(last, [])
            else:
                _dict[a] = True
        else:
            _dict[last].append(a)
            last = '_'
    if not bare_args and invalid_exc and _dict['_']:
       raise invalid_exc('Invalid arguments: %s' % ' '.join(_dict['_']))
    return _dict


def cute_str(txt, quotes=''):
    try:
        return '%s%s%s' % (
            quotes,
            str(txt, 'utf-8') if isinstance(txt, bytes) else txt,
            quotes)
    except UnicodeDecodeError:
        return '%s' % txt


def pmkdir(path, mode):
    if not os.path.exists(path):
        pmkdir(os.path.dirname(path), mode)
        os.mkdir(path, mode)


def _json_object_prop(name):
    return (lambda s: s._dict[name], lambda s,v: s._setitem(name, v))


class _json_encoder(json.JSONEncoder):
    def encode(self, o):
        if hasattr(o, '__json__'):
            return o.__json__()
        return super().encode(o)

    def default(self, o):
        if hasattr(o, '_dict'):
            return o._dict
        return super().default(o)


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


class _json_object():
    _KEYS = {}

    def __init__(self, *others, **keyword_values):
        self._dict = {}

        # This is a naughty hack to avoid polluting our pydoc output
        # with trivial methods.
        self.items = self._dict.items

        if others or keyword_values:
            self.update(*others, **keyword_values)
            self._check_self()
        else:
            self._set_defaults()

    def update(self, *others, **keyword_values):
        for o in others:
            self._update(o)
        if keyword_values:
            self._update(keyword_values)
        return self

    def __contains__(self, key):
        return (key in self._KEYS and self._dict.__contains__(key))

    def _check_self(self):
        pass

    def _set_defaults(self):
        pass

    def _validate(self, key, value):
        if key not in self._KEYS:
            raise KeyError("Invalid key: %s" % key)
        return self._KEYS[key](value)

    def _update(self, other):
        """Copy all key/value pairs from `other` into this object."""
        for k, v in other.items():
            self._setitem(k.replace('_', '-'), v)
        return self

    def _setitem(self, key, value):
        self._dict[key] = self._validate(key, value)

    def __json__(self):
        return str(self)

    def __str__(self):
        return json.dumps(self._dict, indent=2, cls=_json_encoder)


class _encrypted_json_object(_json_object):
    def __init__(self, *args, **kwargs):
        self.encrypted_data = None
        self.encryption_key = None
        if len(args) == 1 and isinstance(args[0], str):
            self.encrypted_data = args[0]
            super().__init__(self, **kwargs)
        else:
            super().__init__(self, *args, **kwargs)

    def encrypt(self, key, compress=False):
        iv = random_bytes(16)  # == 128 bits
        ed = bytes(str(self), 'utf-8')
        if compress:
            ed = zlib.compress(ed, 9)
        ed = aesgcm_encrypt(key, iv, ed)
        self.encryption_key = str(base64.b64encode(key), 'utf-8')
        self.encrypted_data = str(base64.b64encode(iv+ed), 'utf-8')
        return self

    def decrypt(self, key, decompress=False):
        ed = base64.b64decode(self.encrypted_data)
        ed = aesgcm_decrypt(key, ed[:16], ed[16:])
        if decompress:
            ed = zlib.decompress(ed)
        self.update(json.loads(ed))
        self.encrypted_data = None
        self.encryption_key = None
        return self

    def __str__(self):
        if self.encrypted_data is not None:
            return self.encrypted_data
        return super().__str__()
