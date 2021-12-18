import time

from .proto import PaymentScheme

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .aes_utils import aesgcm_key_to_int, aesgcm_key_from_int


PAYMENT_HANDLERS = {}


def register_payment_handlers(*classes):
    global PAYMENT_HANDLERS
    for cls in classes:
        PAYMENT_HANDLERS[cls.SCHEME] = cls


def make_payment(policy, data):
    global PAYMENT_HANDLERS
    return PAYMENT_HANDLERS[policy.scheme].MakePayment(policy, data)


class PaymentFree:
    SCHEME = 'free'

    def __init__(self, value):
        self.value = value 

        self.policy = PaymentScheme()
        self.policy.scheme = self.SCHEME
        self.policy.scheme_id = self.SCHEME
        self.policy.description = 'Freebies'
        self.policy.expiration_seconds = value

    scheme_id = property(lambda s: s.policy.scheme_id)
    description = property(lambda s: s.policy.description)

    @classmethod
    def MakePayment(self, policy, data):
        return '%s:0' % policy.scheme_id

    def get_policy(self, user_auth_FIXME):
        return self.policy

    def process(self, cash, data):
        return self.value


class PaymentHashcash(PaymentFree):
    SCHEME = 'hashcash'

    SCRYPT_LENGTH = (128 // 8)
    SCRYPT_N = 2**8
    SCRYPT_R = 8
    SCRYPT_P = 1

    def __init__(self, storage, bits, value):
        PaymentFree.__init__(self, value)

        self.storage = storage

        self.policy.hashcash_bits = bits
        self.policy.scheme_id = '%s-%d' % (self.SCHEME, bits)
        self.policy.description = (
            '%d-bit scrypt(len=%d,n=%d,r=%d,p=%d) collisions' % (
                bits,
                self.SCRYPT_LENGTH,
                self.SCRYPT_N, self.SCRYPT_R, self.SCRYPT_P))

        self.bits = bits
        self.bitmask = self._bitmask(self.policy)

    @classmethod
    def _bitmask(cls, policy):
        bitmask = 0
        for i in range(0, policy.hashcash_bits):
            bitmask *= 2
            bitmask |= 1
        return bitmask

    @classmethod
    def _scrypt(cls, counter, ts, data):
        kdf = Scrypt(
            salt=b'',
            length=cls.SCRYPT_LENGTH,
            n=cls.SCRYPT_N,
            r=cls.SCRYPT_R,
            p=cls.SCRYPT_P,
            backend=default_backend())
        return kdf.derive(b''.join([data, b'%x' % counter, b'%x' % ts, data]))

    @classmethod
    def MakePayment(cls, policy, data, maxtime=90):
        data = data if isinstance(data, bytes) else bytes(data, 'utf-8')
        bitmask = cls._bitmask(policy)
        now = int(time.time())
        deadline = now + maxtime
        counter = 0
        while now < deadline:
            counter += 1
            scrypt_cnd = aesgcm_key_to_int(cls._scrypt(counter, now, data))
            if (scrypt_cnd & bitmask) == 0:
                return '%s:%x-%x' % (policy.scheme_id, counter, now)
            now = int(time.time())
        raise ValueError('HashCash not found after %d seconds' % maxtime)

    def process(self, cash, data, now=None):
        now = int(now or time.time())
        data = data if isinstance(data, bytes) else bytes(data, 'utf-8')
        counter, ts = cash.split('-')
        counter = int(counter, 16)
        ts = int(ts, 16)

        # Collisions are only valid for 2 minutes, with a minor allowance
        # for clocks being out of sync.
        if not (now-125 < ts < now+5):
            return 0

        scrypt_ctd = aesgcm_key_to_int(self._scrypt(counter, ts, data))
        if (scrypt_ctd & self.bitmask) == 0:
            return self.value
        else:
            return 0


register_payment_handlers(PaymentFree, PaymentHashcash)


if __name__ == '__main__':
    import time, math
    data = b'012345678' * 128
    stop = time.time() + 4
    counter = 0
    while time.time() < stop:
        counter += 1
        PaymentHashcash._scrypt(counter, int(stop), data)

    # Note: We add 1 bit to to the collision estimate, because on average
    #       a collision should be found after checking half the space.
    print('%d iterations in %.1f seconds = %.2f bit collision?'
        % (counter, time.time() - stop + 1, math.log(counter, 2) + 1))

