---
title: Hextrap
date: 2026-06-26
tags:
- crypto
- V1T-CTF-2026
---

- **Challenge:** Hextrap
- **Category:** Crypto
- **Flag:** `v1t{six_twists_one_smooth_order}`

---

## My initial read / first impressions

We are given a Python script `chall.py` and an output file with `n`, `e`, and `c`.

At first glance, this looks like normal RSA:

```python
p = special_prime(BITS, SMOOTH_BOUND)
q = number.getPrime(BITS)
n = p * q
phi = (p - 1) * (q - 1)

d = pow(E, -1, phi)

key = RSA.construct((n, E, d, p, q))
cipher = PKCS1_OAEP.new(key)
```

The public exponent is the usual `65537`, the ciphertext uses RSA OAEP, and the modulus is just `n = p*q`.

So the goal is obvious: factor `n`, recover the private key, and decrypt the ciphertext.

The suspicious part is how `p` is generated. `q` is a normal random prime, but `p` is generated using this custom function:

```python
p = special_prime(BITS, SMOOTH_BOUND)
```

That immediately tells us the challenge is probably not attacking RSA directly. Instead, we are supposed to use the weird structure hidden inside `p`.

## Understanding the weird norm

The script defines this function:

```python
def hnorm(z):
    x, y = z
    return x*x - x*y + y*y
```

This is not a random formula. It is the norm form for Eisenstein integers.

The multiplication function also confirms that we are working in that ring:

```python
def hmul(z, w):
    x, y = z
    u, v = w
    return (x*u - y*v, x*v + y*u - y*v)
```

So instead of just picking a random prime, the challenge constructs some Eisenstein integer `z`, takes its norm, and uses that structure to create `p`.

The prime generation eventually does this:

```python
z, m = smooth_hex(bits, bag)
x, y = z
p = hnorm((x - 1, y))
```

The important part is that `z` is built so that its norm is smooth.

```python
SMOOTH_BOUND = 2**15
```

So `hnorm(z)` is composed only of small prime factors up to `2^15`.

That is the dangerous structure. The prime `p` is not random. It is related to a smooth norm in the Eisenstein integers.

## The Vulnerability

For RSA, factoring `n` is supposed to be hard because both primes are random.

Here, one prime is random, but the other prime has special hidden structure.

The challenge title says "Norms can hide dangerous structure", and that is exactly what happens. The smooth norm does not directly give us `p`, but it creates a smooth group order on a special family of elliptic curves.

The relevant curves are the `j = 0` curves:

```text
y^2 = x^3 + b
```

These curves have complex multiplication by Eisenstein integers. Since the prime `p` was created using Eisenstein norm structure, one of the sextic twists of these curves over `F_p` has smooth order.

In normal ECM, you pick random elliptic curves and hope that the group order modulo one of the prime factors is smooth. If it is smooth, multiplying a point by a huge smooth multiple causes the computation to fail modulo `n`, and the failure leaks a factor.

Here, the challenge basically rigs the game. Because of how `p` was generated, one of these `j = 0` curves is guaranteed to have a very smooth order modulo `p`.

So instead of general-purpose factoring, we can run a custom ECM attack using curves of the form:

```text
y^2 = x^3 + b
```

and a smoothness bound of `2^15`.

## The Logic

We do not know `p`, but we do know:

```text
n = p*q
```

We pick a random curve over `Z/nZ`:

```text
E: y^2 = x^3 + b
```

Then we pick a random point on it by choosing random `x` and `y`, and defining:

```text
b = y^2 - x^3 mod n
```

Now the point `(x, y)` is automatically on the curve.

Next, we compute:

```text
K = lcm(1, 2, 3, ..., 2^15)
```

This number contains all prime powers up to the smoothness bound.

If the order of the point modulo `p` divides `K`, then:

```text
K * P = O mod p
```

But the same thing will almost certainly not happen modulo `q`, because `q` is just random.

When doing elliptic curve arithmetic modulo composite `n`, this mismatch causes a denominator or projective `z` coordinate to share a nontrivial gcd with `n`.

So after computing `K*P`, we check:

```python
g = gcd(z_coordinate, n)
```

If:

```text
1 < g < n
```

then we found a factor of `n`.

This is exactly the ECM idea, except the challenge made the curve family and smoothness bound very intentional.

## Decrypting RSA

Once we factor `n`, the rest is standard RSA.

We compute:

```text
phi = (p - 1)(q - 1)
d = e^-1 mod phi
```

Then decrypt:

```text
m = c^d mod n
```

The only slightly annoying part is that the challenge uses RSA OAEP, not raw RSA. So after the modular exponentiation, we still need to remove the OAEP padding.

PyCryptodome could do this if we construct the private key correctly, but I just manually decoded OAEP using SHA1, which is the default for `PKCS1_OAEP`.

## Solution Script

Here is the final solve script.

```python
import random
import math
import re
import hashlib
from pathlib import Path

txt = Path("output.txt").read_text()

n = int(re.search(r"n = (\d+)", txt).group(1))
e = int(re.search(r"e = (\d+)", txt).group(1))
c = int(re.search(r"c = ([0-9a-f]+)", txt).group(1), 16)

B = 2**15

def primes_upto(n):
    sieve = bytearray(b"\x01") * (n + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, math.isqrt(n) + 1):
        if sieve[i]:
            start = i * i
            sieve[start:n+1:i] = b"\x00" * (((n - start) // i) + 1)
    return [i for i in range(n + 1) if sieve[i]]

K = 1
for p in primes_upto(B):
    pp = p
    while pp * p <= B:
        pp *= p
    K *= pp

O = (0, 1, 0)

def dbl(P):
    X1, Y1, Z1 = P

    if Z1 % n == 0 or Y1 % n == 0:
        return O

    XX = X1 * X1 % n
    YY = Y1 * Y1 % n
    YYYY = YY * YY % n
    S = 4 * X1 * YY % n
    M = 3 * XX % n
    X3 = (M * M - 2 * S) % n
    Y3 = (M * (S - X3) - 8 * YYYY) % n
    Z3 = 2 * Y1 * Z1 % n

    return (X3, Y3, Z3)

def add(P, Q):
    X1, Y1, Z1 = P
    X2, Y2, Z2 = Q

    if Z1 % n == 0:
        return Q
    if Z2 % n == 0:
        return P

    Z1Z1 = Z1 * Z1 % n
    Z2Z2 = Z2 * Z2 % n
    U1 = X1 * Z2Z2 % n
    U2 = X2 * Z1Z1 % n
    S1 = Y1 * Z2 * Z2Z2 % n
    S2 = Y2 * Z1 * Z1Z1 % n

    H = (U2 - U1) % n
    r = 2 * (S2 - S1) % n

    if H == 0:
        if r == 0:
            return dbl(P)
        return O

    I = (2 * H) ** 2 % n
    J = H * I % n
    V = U1 * I % n

    X3 = (r * r - J - 2 * V) % n
    Y3 = (r * (V - X3) - 2 * S1 * J) % n
    Z3 = (((Z1 + Z2) % n) ** 2 - Z1Z1 - Z2Z2) % n
    Z3 = Z3 * H % n

    return (X3, Y3, Z3)

def mul(P, k):
    R = O
    Q = P

    while k:
        if k & 1:
            R = add(R, Q)
        k >>= 1
        if k:
            Q = dbl(Q)

    return R

random.seed(1)
factor = None

for i in range(1, 200):
    x = random.randrange(2, n - 1)
    y = random.randrange(2, n - 1)
    b = (y * y - x * x * x) % n

    g = math.gcd(27 * b * b, n)
    if 1 < g < n:
        factor = g
        break

    P = (x, y, 1)
    R = mul(P, K)
    g = math.gcd(R[2], n)

    if 1 < g < n:
        factor = g
        print(f"[+] factor found on curve {i}")
        break

p = factor
q = n // p

print("[+] p =", p)
print("[+] q =", q)

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

k = (n.bit_length() + 7) // 8
em = pow(c, d, n).to_bytes(k, "big")

def mgf1(seed, length, h=hashlib.sha1):
    out = b""
    counter = 0

    while len(out) < length:
        out += h(seed + counter.to_bytes(4, "big")).digest()
        counter += 1

    return out[:length]

def oaep_decode(em, label=b"", h=hashlib.sha1):
    hlen = h().digest_size

    masked_seed = em[1:1+hlen]
    masked_db = em[1+hlen:]

    seed_mask = mgf1(masked_db, hlen, h)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))

    db_mask = mgf1(seed, len(em) - hlen - 1, h)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

    lhash = h(label).digest()

    assert em[0] == 0
    assert db[:hlen] == lhash

    rest = db[hlen:]
    idx = rest.index(b"\x01")

    assert all(x == 0 for x in rest[:idx])

    return rest[idx+1:]

flag = oaep_decode(em)

print(flag.decode())
```

Running it gives:

```text
[+] factor found on curve 4
[+] p = 1175767572539182004412802112515708953362201049446828214148067585832276198566987622360670796066262494782140237777447566663228660057019918970734753555793208399
[+] q = 12659730420279195395727689953489569910556280521198113846263228396293965178341816044443208273233252338809773858532292514048792161768300803782516175540948494621
v1t{six_twists_one_smooth_order}
```

## Final Thoughts

The mistake was not in RSA-OAEP itself. The encryption was fine once the RSA key exists.

The entire issue was the prime generation. One RSA prime was generated with hidden Eisenstein norm structure, and that structure made one of the related elliptic curve group orders smooth.

Because of that, ECM becomes extremely fast. We only need to try a few `j = 0` curves before the smooth order leaks a factor of `n`.

So the takeaway is pretty simple: RSA primes need to be random primes. Adding cute algebraic structure to prime generation can completely destroy the security, even if the final RSA encryption code looks normal.
