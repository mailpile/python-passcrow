import os
import struct
import time

import cryptography.hazmat.backends
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


DEFAULT_ASSOC_DATA = b'Passcrow Encrypted Data'


def random_bytes(_bytes=16):
    return os.urandom(_bytes)


# Note: The default n_factor=20 is quite high, and will take some time.
def derive_aesgcm_key(*key, salt=b'', n_factor=20, length=256):
    assert(length in (128, 192, 256))
    kdf = Scrypt(
        salt=salt,
        length=(length//8),
        n=2**n_factor,
        r=8,
        p=1,
        backend=cryptography.hazmat.backends.default_backend())
    return kdf.derive(b''.join(key))


def random_aesgcm_key(length=256, insecure=False):
    # Stretching with the time and PID are a weak defense, in case the OS
    # is giving us very lame random data. We use a lower n_factor to save
    # cycles. The "insecure" mode is for generating keys which are only used
    # for testing or validation.
    return derive_aesgcm_key(
        random_bytes(length // 4),
        bytes(str(os.getpid()), 'latin-1'),
        bytes(str(time.time()), 'latin-1'),
        n_factor=(4 if insecure else 14),
        length=length)


def aesgcm_key_to_int(bin_key):
    int_key = 0
    for b in bin_key:
        int_key *= 256
        int_key += b
    return int_key

def aesgcm_key_from_int(int_key):
    bin_key = bytearray()
    while int_key:
        bin_key.append(int_key % 256)
        int_key //= 256
    return bytes(reversed(bin_key))


def aesgcm_encrypt(key, nonce, data, aad=DEFAULT_ASSOC_DATA):
    return AESGCM(key).encrypt(nonce, data, aad)


def aesgcm_decrypt(key, nonce, data, aad=DEFAULT_ASSOC_DATA):
    return AESGCM(key).decrypt(nonce, data, aad)


if __name__ == "__main__":
    import base64

    bogus_key = derive_aesgcm_key(b"01234567890abcdef", n_factor=10)
    bogus_nonce = b"this is a bogus nonce that is bogus"
    hello = b"hello world"

    results = []

    ct1 = aesgcm_encrypt(bogus_key, bogus_nonce, hello)

    assert(bogus_key == aesgcm_key_from_int(aesgcm_key_to_int(bogus_key)))

    assert(ct1 != hello)  # lol
    assert(len(random_aesgcm_key(insecure=True)) == len(bogus_key))
    assert(aesgcm_decrypt(bogus_key, bogus_nonce, ct1) == hello)

    print("ok")
