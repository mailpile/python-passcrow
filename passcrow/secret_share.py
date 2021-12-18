"""
The following Python implementation of Shamir's Secret Sharing is
released into the Public Domain under the terms of CC0 and OWFa:
https://creativecommons.org/publicdomain/zero/1.0/
http://www.openwebfoundation.org/legal/the-owf-1-0-agreements/owfa-1-0

See the bottom few lines for usage. Tested on Python 2 and 3.

Source: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
"""

from __future__ import division
from __future__ import print_function

import random


# 12th Mersenne Prime
# (for this application we want a known prime number as close as
# possible to our security level; e.g.  desired security level of 128
# bits -- too large and all the ciphertext is large; too small and
# security is compromised)
#_PRIME = 2 ** 127 - 1
# 13th Mersenne Prime is 2**521 - 1


# Modified for passcrow: Use the 13th Mersenne; these are rare
# operations and we are not space-constrained. So we may as well
# indulge in excessive security. This will not be a compatibility
# constraint, since the protocol and server are agnostic about the
# actual secret sharing / recovery implementation.
_PRIME = 2 ** 521 - 1


def random_int(_maxint):
    # From `pydoc random.SystemRandom`:
    # | Alternate random number generator using sources provided
    # | by the operating system (such as /dev/urandom on Unix or
    # | CryptGenRandom on Windows).
    return  random.SystemRandom().randint(0, _maxint)


def _eval_at(poly, x, prime):
    """Evaluates polynomial (coefficient tuple) at x, used to generate a
    shamir pool in make_random_shares below.
    """
    accum = 0
    for coeff in reversed(poly):
        accum *= x
        accum += coeff
        accum %= prime
    return accum

def make_random_shares(secret, minimum, shares, prime=_PRIME):
    """
    Generates a random shamir pool for a given secret, returns share points.
    """
    if minimum > shares or minimum < 3:
        raise ValueError("Pool secret would be irrecoverable.")
    poly = [secret] + [random_int(prime - 1) for i in range(minimum - 1)]
    points = ['%x-%x' % (i, _eval_at(poly, i, prime))
              for i in range(1, shares + 1)]
    return points

def _extended_gcd(a, b):
    """
    Division in integers modulus p means finding the inverse of the
    denominator modulo p and then multiplying the numerator by this
    inverse (Note: inverse of A is B such that A*B % p == 1) this can
    be computed via extended Euclidean algorithm
    http://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Computation
    """
    x = 0
    last_x = 1
    y = 1
    last_y = 0
    while b != 0:
        quot = a // b
        a, b = b, a % b
        x, last_x = last_x - quot * x, x
        y, last_y = last_y - quot * y, y
    return last_x, last_y

def _divmod(num, den, p):
    """Compute num / den modulo prime p

    To explain what this means, the return value will be such that
    the following is true: den * _divmod(num, den, p) % p == num
    """
    inv, _ = _extended_gcd(den, p)
    return num * inv

def _lagrange_interpolate(x, x_s, y_s, p):
    """
    Find the y-value for the given x, given n (x, y) points;
    k points will define a polynomial of up to kth order.
    """
    k = len(x_s)
    assert k == len(set(x_s)), "points must be distinct"
    def PI(vals):  # upper-case PI -- product of inputs
        accum = 1
        for v in vals:
            accum *= v
        return accum
    nums = []  # avoid inexact division
    dens = []
    for i in range(k):
        others = list(x_s)
        cur = others.pop(i)
        nums.append(PI(x - o for o in others))
        dens.append(PI(cur - o for o in others))
    den = PI(dens)
    num = sum([_divmod(nums[i] * den * y_s[i] % p, dens[i], p)
               for i in range(k)])
    return (_divmod(num, den, p) + p) % p

def recover_secret(shares, prime=_PRIME):
    """
    Recover the secret from share points
    (x, y points on the polynomial).
    """
    if len(shares) < 3:
        raise ValueError("need at least three shares")
    def _dec(s):
        x, y = s.split('-')
        return (int(x, 16), int(y, 16))
    x_s, y_s = zip(*[_dec(s) for s in shares])
    return _lagrange_interpolate(0, x_s, y_s, prime)


def main():
    """Main function"""
    secret = random_int(2**128)
    shares = make_random_shares(secret, minimum=3, shares=8)

    print('Secret:                                                     ',
          '%x' % secret)
    print('Shares:')
    if shares:
        for share in shares:
            print('  ', share)

    print('Secret recovered from minimum subset of shares:             ',
          '%x' % recover_secret(shares[:3]))
    print('Secret recovered from a different minimum subset of shares: ',
          '%x' % recover_secret(shares[-3:]))

if __name__ == '__main__':
    main()
