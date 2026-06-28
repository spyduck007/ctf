---
title: Hyperelliptic Drift
date: 2026-06-28
tags:
- crypto
- MntcrlCTF-2026
---

- **Challenge:** Hyperelliptic Drift
- **Category:** Crypto
- **Flag:** `mntcrl{m_u_m_f_o_r_d_s_d_r_i_f_t_i_n_g_l_a_t_t_i_c_e_3144ec84df478805}`

---

## My initial read / first impressions

We are given a crypto challenge with the description:

```text
This is the new, perfect, and unbreakable signing method, with a new unbreakable prng
```

Whenever a challenge says something is "perfect" and "unbreakable", it is usually extremely breakable.

The remote gives us a menu:

```text
--- Hyperelliptic Drift ---
1. Get Public Key
2. Sign Message
3. Get Flag
4. Exit
```

The goal is pretty direct. We can ask the server to sign messages, and to get the flag we need to submit the ECDSA private key.

The files given are small:

* `Dockerfile`
* `docker-compose.yml`
* `app.py`

The important file is obviously `app.py`.

## Looking at the signing code

The server generates a private key and public key on secp256k1:

```python
E_CURVE = EllipticCurve(
    GF(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F),
    [0, 7],
)
G_GEN = E_CURVE.gens()[0]
N_ORDER = G_GEN.order()
```

Then the signing code is normal ECDSA:

```python
z = int(hashlib.sha256(msg.encode()).hexdigest(), 16)
k = self.prng.get_nonce() % N_ORDER
K = k * G_GEN
r = int(K.xy()[0]) % N_ORDER
s = (pow(k, -1, N_ORDER) * (z + r * self.priv_key)) % N_ORDER
```

So each signature gives us:

```text
r, s, z
```

and internally:

```text
s = k^-1 * (z + r*d) mod n
```

where `d` is the private key.

At first glance, this is just standard ECDSA. So the only real place to look is the nonce generation.

## The PRNG

The challenge has this fancy looking PRNG:

```python
class HyperPS3PRNG:
    def __init__(self):
        self.p_ecc = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        self.F = GF(self.p_ecc)
        self.R_poly = self.F["x"]
        x = self.R_poly.gen()

        self.f_hyper = x**5 + 2 * x**3 + x + 1337
        self.C = HyperellipticCurve(self.f_hyper)
        self.J = self.C.jacobian()

        self.P_step = self._rand_jac_elem()
        self.state = self._rand_jac_elem()
        self.S = randint(1, self.p_ecc)
```

It uses a hyperelliptic curve Jacobian, updates the state like this:

```python
self.state = self.S * self.state + self.P_step
```

and then extracts the nonce like this:

```python
u = self.state[0]
coeffs = u.list()
u1 = int(coeffs[1]) if len(coeffs) > 1 else 0
u0 = int(coeffs[0]) if len(coeffs) > 0 else 0
return (u1 ^ u0) & ((1 << 192) - 1)
```

This is the whole bug.

The PRNG can be as fancy as it wants, but the final output is masked down to 192 bits:

```python
& ((1 << 192) - 1)
```

ECDSA on secp256k1 needs a nonce modulo a roughly 256-bit group order. But here every nonce is smaller than `2^192`.

So every signature leaks that the top 64 bits of the nonce are zero.

That is enough to recover the private key with a Hidden Number Problem lattice attack.

## The Vulnerability

ECDSA gives:

```text
s*k = z + r*d mod n
```

Rearranging:

```text
k = s^-1*z + s^-1*r*d mod n
```

For each signature, define:

```text
a_i = z_i * s_i^-1 mod n
t_i = r_i * s_i^-1 mod n
```

Then:

```text
k_i = a_i + t_i*d mod n
```

Normally `k_i` is random modulo `n`, so this does not help.

But in this challenge:

```text
0 <= k_i < 2^192
```

So for every signature, `a_i + t_i*d mod n` is unusually small.

That is exactly the Hidden Number Problem. With enough signatures, LLL can recover `d`.

I collected 32 signatures, built the lattice, ran LLL, and then tested candidates by checking if all reconstructed nonces were below `2^192`.

The nice thing is that this avoids needing to care about the actual Sage generator point. We do not need to verify the public key with our own EC math. We can just check the small nonce condition directly:

```text
k_i = (z_i + r_i*d) * s_i^-1 mod n
```

If the candidate is correct, every `k_i` will be small.

## Why this works

The server thinks it is safe because the nonce comes from some complicated hyperelliptic curve construction.

But ECDSA does not care how complicated the PRNG looks internally. The only thing that matters is whether the final nonce is unpredictable and full-sized.

Here the nonce is always only 192 bits.

That means every signature leaks a bound on `k`, and many bounded nonces are enough to recover the signing key.

So the "new unbreakable prng" is basically just:

```text
fancy math -> throw away 64 bits -> lattice attack
```

## Solution Script

Here is the final solve script.

It collects signatures from the remote, runs LLL, recovers the private key, and submits it to get the flag.

You need `fpylll` installed:

```bash
python3 -m pip install fpylll cysignals
```

```python
import hashlib
import json
import re
import socket
import ssl

from fpylll import IntegerMatrix, LLL


HOST = "hyperelliptic-drift-50d1836c7bef.c.mntcrl.it"
PORT = 443

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
B = 1 << 192
NUM_SIGS = 32


def invmod(x, m):
    return pow(x % m, -1, m)


class Tube:
    def __init__(self):
        raw = socket.create_connection((HOST, PORT), timeout=15)
        ctx = ssl.create_default_context()
        self.s = ctx.wrap_socket(raw, server_hostname=HOST)
        self.buf = b""

    def recvuntil(self, marker):
        marker = marker.encode()
        while marker not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk:
                raise EOFError("closed")
            self.buf += chunk

        idx = self.buf.index(marker) + len(marker)
        out = self.buf[:idx]
        self.buf = self.buf[idx:]
        return out.decode(errors="replace")

    def sendline(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.s.sendall(data + b"\n")


def recover_priv(sigs):
    m = len(sigs)
    W = N // B

    ts = []
    aas = []

    for r, s, z in sigs:
        si = invmod(s, N)
        ts.append((r * si) % N)
        aas.append((z * si) % N)

    M = IntegerMatrix(m + 2, m + 2)

    for i in range(m):
        M[i, i] = N * W

    for i, t in enumerate(ts):
        M[m, i] = t * W

    M[m, m] = 1

    for i, a in enumerate(aas):
        M[m + 1, i] = a * W

    M[m + 1, m + 1] = N

    LLL.reduction(M, delta=0.99)

    def score(d):
        total = 0
        for r, s, z in sigs:
            k = ((z + r * d) * invmod(s, N)) % N
            if k < B:
                total += 1
        return total

    best = (0, 0)
    tried = set()

    for row in range(m + 2):
        for col in range(m + 2):
            val = int(M[row, col])
            for cand in (val % N, (-val) % N):
                if cand == 0 or cand in tried:
                    continue

                tried.add(cand)
                sc = score(cand)

                if sc > best[0]:
                    best = (sc, cand)

                if sc == m:
                    return cand

    raise RuntimeError(f"no key found, best score was {best[0]}/{m}")


def main():
    io = Tube()
    io.recvuntil("> ")

    sigs = []

    for i in range(NUM_SIGS):
        msg = f"msg-{i}"

        io.sendline("2")
        io.recvuntil("Message to sign: ")
        io.sendline(msg)

        out = io.recvuntil("> ")
        blob = re.search(r"\{.*\}", out).group(0)
        data = json.loads(blob)

        r = int(data["r"], 16)
        s = int(data["s"], 16)
        z = int(data["z"], 16)

        sigs.append((r, s, z))
        print(f"[+] signature {i + 1}/{NUM_SIGS}")

    d = recover_priv(sigs)

    print(f"[+] private key = {hex(d)}")

    io.sendline("3")
    io.recvuntil("Private key (hex): ")
    io.sendline(hex(d)[2:])

    print(io.recvuntil("}"))


if __name__ == "__main__":
    main()
```

Running it:

```bash
python3 solve.py
```

Output:

```text
[+] signature 1/32
[+] signature 2/32
[+] signature 3/32
[+] signature 4/32
[+] signature 5/32
[+] signature 6/32
[+] signature 7/32
[+] signature 8/32
[+] signature 9/32
[+] signature 10/32
[+] signature 11/32
[+] signature 12/32
[+] signature 13/32
[+] signature 14/32
[+] signature 15/32
[+] signature 16/32
[+] signature 17/32
[+] signature 18/32
[+] signature 19/32
[+] signature 20/32
[+] signature 21/32
[+] signature 22/32
[+] signature 23/32
[+] signature 24/32
[+] signature 25/32
[+] signature 26/32
[+] signature 27/32
[+] signature 28/32
[+] signature 29/32
[+] signature 30/32
[+] signature 31/32
[+] signature 32/32
[+] private key = 0x756d8cd33895164a72176df45ad941f6b27cb99c8902a77ffec0cf040a7f85bd
WIN! mntcrl{m_u_m_f_o_r_d_s_d_r_i_f_t_i_n_g_l_a_t_t_i_c_e_3144ec84df478805}
```

And that gives the flag.

## Final thoughts

The hyperelliptic curve stuff is mostly there to look scary.

The actual issue is much simpler: the ECDSA nonce is only 192 bits. Once I noticed that mask, the rest of the challenge became a pretty standard partial nonce leakage attack.

So the solve is:

1. Ask for a bunch of signatures.
2. Convert each signature into a Hidden Number Problem equation.
3. Use LLL to recover the private key.
4. Submit the private key.
5. Get the flag.