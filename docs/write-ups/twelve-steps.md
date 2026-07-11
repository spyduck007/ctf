---
title: Twelve Steps
date: 2026-07-06
tags:
- crypto
- LYKNCTF
---

- **Challenge:** Twelve Steps
- **Category:** Crypto
- **Flag:** `LYKNCTF{ef573b28686144bc98557e99ff3191ec}`

---

## My initial read / first impressions

The challenge description is very short:

```text
Twelve numbers. One question. What comes next?
```

Connecting to the service gives the full setup immediately:

```bash
nc 51.79.140.18 16463
```

The server prints:

```text
My generator: s_{n+1} = (a*s_n + c) mod m  (a, c, m, seed all secret)
Here are 12 consecutive outputs:
out[0] = ...
out[1] = ...
...
out[11] = ...
Predict out[12] to earn the flag.
out[12] =
```

So this is not really a mystery PRNG challenge. The service tells us it is using a linear congruential generator:

```text
s_{n+1} = (a*s_n + c) mod m
```

The only hidden values are `a`, `c`, `m`, and the seed. But since we get 12 consecutive outputs, that is way too much leakage for an LCG. Linear randomness is no randomness at all.

## Recovering the modulus

Let the consecutive outputs be:

```text
s0, s1, s2, ..., s11
```

Define the differences:

```text
t_i = s_{i+1} - s_i
```

Because this is an LCG:

```text
s_{i+1} = a*s_i + c mod m
```

Subtracting two consecutive equations cancels out `c`:

```text
t_{i+1} = a*t_i mod m
```

That means:

```text
t_{i+2} * t_i = a*t_{i+1} * t_i mod m
```

and also:

```text
t_{i+1}^2 = a*t_i * t_{i+1} mod m
```

So the useful relation is:

```text
t_{i+2} * t_i - t_{i+1}^2 = 0 mod m
```

In other words, every value of:

```text
(diffs[i + 2] * diffs[i]) - (diffs[i + 1] ** 2)
```

is divisible by the hidden modulus `m`.

So the first step is just taking a gcd of all those expressions:

```python
g = 0
for i in range(len(diffs) - 2):
    z = diffs[i + 2] * diffs[i] - diffs[i + 1] * diffs[i + 1]
    g = gcd(g, abs(z))
```

Most of the time, this directly gives the modulus. If the gcd is a multiple of the real modulus instead, we can factor it and try divisors until one works.

## Recovering `a` and `c`

Once we have a candidate modulus `m`, recovering the rest is easy.

From:

```text
t_{i+1} = a*t_i mod m
```

we get:

```text
a = t_{i+1} * inverse(t_i) mod m
```

Then recover `c` from any known state transition:

```text
c = s_{i+1} - a*s_i mod m
```

The only minor annoyance is that not every `t_i` is guaranteed to be invertible modulo `m`, so the script just tries each pair of differences until it finds one where `gcd(t_i, m) == 1`.

After that, it verifies the recovered parameters against all 12 leaked outputs. If every transition matches, we can compute:

```text
out[12] = (a*out[11] + c) mod m
```

and send it back to the service.

## Solution Script

Here is the final solve script I used. It connects to the service, parses the 12 outputs, recovers the LCG, predicts the next value, and submits it automatically.

```python
#!/usr/bin/env python3
import math
import random
import re
import socket
from collections import Counter

HOST = "51.79.140.18"
PORT = 16463


def recv_until(sock, marker, timeout=5):
    sock.settimeout(timeout)
    data = b""

    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk

    return data


def recv_rest(sock, timeout=3):
    sock.settimeout(timeout)
    data = b""

    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break

    return data


def is_probable_prime(n):
    if n < 2:
        return False

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]

    for p in small_primes:
        if n % p == 0:
            return n == p

    d = n - 1
    s = 0

    while d % 2 == 0:
        s += 1
        d //= 2

    for a in small_primes:
        if a >= n:
            continue

        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        good = False
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                good = True
                break

        if not good:
            return False

    return True


def pollard_rho(n):
    if n % 2 == 0:
        return 2

    while True:
        c = random.randrange(1, n - 1)
        x = random.randrange(2, n - 1)
        y = x
        d = 1

        def f(v):
            return (pow(v, 2, n) + c) % n

        while d == 1:
            x = f(x)
            y = f(f(y))
            d = math.gcd(abs(x - y), n)

        if d != n:
            return d


def factor(n, out):
    if n == 1:
        return

    if is_probable_prime(n):
        out.append(n)
        return

    d = pollard_rho(n)
    factor(d, out)
    factor(n // d, out)


def divisors_from_factors(factors):
    counts = Counter(factors)
    divisors = [1]

    for p, e in counts.items():
        current = []
        mul = 1

        for _ in range(e + 1):
            for d in divisors:
                current.append(d * mul)
            mul *= p

        divisors = current

    return sorted(divisors, reverse=True)


def try_modulus(states, m):
    if m <= max(states):
        return None

    diffs = [states[i + 1] - states[i] for i in range(len(states) - 1)]

    for i in range(len(diffs) - 1):
        d0 = diffs[i] % m
        d1 = diffs[i + 1] % m

        if math.gcd(d0, m) != 1:
            continue

        a = (d1 * pow(d0, -1, m)) % m
        c = (states[i + 1] - a * states[i]) % m

        valid = True
        for j in range(len(states) - 1):
            if (a * states[j] + c) % m != states[j + 1]:
                valid = False
                break

        if valid:
            nxt = (a * states[-1] + c) % m
            return nxt, a, c, m

    return None


def solve_lcg(states):
    diffs = [states[i + 1] - states[i] for i in range(len(states) - 1)]

    g = 0
    for i in range(len(diffs) - 2):
        z = diffs[i + 2] * diffs[i] - diffs[i + 1] * diffs[i + 1]
        g = math.gcd(g, abs(z))

    if g == 0:
        raise ValueError("Could not recover modulus gcd")

    result = try_modulus(states, g)
    if result is not None:
        return result

    print(f"[*] gcd was not directly usable, factoring G = {g}")

    factors = []
    factor(g, factors)

    for m in divisors_from_factors(factors):
        result = try_modulus(states, m)
        if result is not None:
            return result

    raise ValueError("Failed to recover valid LCG parameters")


def main():
    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        banner = recv_until(sock, b"out[12] =", timeout=5)
        text = banner.decode(errors="ignore")
        print(text, end="")

        states = [int(x) for x in re.findall(r"out\[\d+\]\s*=\s*(\d+)", text)]

        if len(states) != 12:
            raise ValueError(f"Expected 12 outputs, got {len(states)}")

        nxt, a, c, m = solve_lcg(states)

        print(f"[+] Recovered m = {m}")
        print(f"[+] Recovered a = {a}")
        print(f"[+] Recovered c = {c}")
        print(f"[+] Predicted out[12] = {nxt}")

        sock.sendall(str(nxt).encode() + b"\n")

        rest = recv_rest(sock)
        print(rest.decode(errors="ignore"))


if __name__ == "__main__":
    main()
```

Running it gave:

```text
[+] Recovered m = 165623101567553
[+] Recovered a = 5246157364019
[+] Recovered c = 51585994169474
[+] Predicted out[12] = 119548906077041
Correct -- linear randomness is no randomness at all.
LYKNCTF{ef573b28686144bc98557e99ff3191ec}
```

## Why this works

An LCG is completely determined by its parameters and one state:

```text
s_{n+1} = (a*s_n + c) mod m
```

The challenge hides the parameters, but leaking 12 consecutive raw outputs gives enough information to recover them. The difference sequence removes `c`, and the determinant-style expression:

```text
t_{i+2} * t_i - t_{i+1}^2
```

is always a multiple of `m`.

Once `m` is known, `a` and `c` follow from basic modular arithmetic. Then predicting `out[12]` is just one more LCG step.

So the whole challenge comes down to the classic LCG weakness: if you reveal enough consecutive outputs, the future outputs are not random anymore.
