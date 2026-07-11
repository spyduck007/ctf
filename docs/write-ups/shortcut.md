---
title: Shortcut
date: 2026-07-06
tags:
- crypto
- LYKNCTF
---

- **Challenge:** Shortcut
- **Category:** Crypto
- **Flag:** `LYKNCTF{abae6bf0e4e7489f9ec472aa8baa3a03}`

---

## My initial read / first impressions

The challenge description says:

```text
Everyone likes shortcuts, including hastily built encryption systems built to meet deadlines. Sometimes the shortest path is the easiest to fall into a trap.
```

Connecting to the service gives one big JSON blob:

```bash
nc 51.79.140.18 15004
```

The important parts look like this:

```json
{
  "N": "1411622589335370161946428866249927560272129140435004924562870441075376725906511032882596063644916635903462484616281218246678496013444281569410382162333689110186736229512709564076243535080662801381724401205619417374138726345598600684755751211655707863442991581421375582950029253155051661161349519662189850770481915018262908484826085270786452911899037600279690351629821783654962312345722458344302590796789724793398345158332256707889688965660215320402115553973159491",
  "e": "375019340998788794396983072797165348823504694978539320768565822820321070835367787535933459855137622756431859786642202388279945092923947994878776566294905474367652812821485683750998645979367017054535618112799153806168096851256353751918381028310164833466208497692497182244374028437262801237270858750203452797676952786218955661677610568474665473892318752854936760176893559958669072153692284559612345402135207670774591757907647117354959800008583160803690654885770477",
  "encrypted_flag": "d9c1f37e39064f98ebc51d81da8d2927fa98314cddc307e64949da42527397dc54ad7520a70deda480",
  "nonce": "4bc54c0a37633f7ae2c604ed",
  "tag": "78adab36e06e6c50fbcc1cf9177feea1",
  "leakage1": {
    "R1": "3707183899162",
    "M1": "4960687226880",
    "R2": "8685480537848",
    "M2": "18034567675904"
  },
  "leakage2": {
    "S": "20",
    "small_value": "110100480"
  },
  "leakage3": {
    "lambda_mod": "4829815997124778648",
    "modulus": "5820058093446234112"
  }
}
```

At first it looks like there are a bunch of weird RSA leakages we are supposed to combine: residues of `p - 1` and `q - 1`, a small gcd involving `p + q`, and a modular leak of `lambda(n)`.

But the challenge name is **Shortcut**, and the public exponent `e` is massive. That usually makes me suspicious of a small private exponent RSA setup. If `d` is too small, then `e / N` leaks enough information through continued fractions to recover `d` directly.

So before trying to do anything with the noisy-looking leakages, I checked for Wiener's attack.

## The actual bug

The generator makes a normal RSA modulus:

```text
N = p * q
phi = (p - 1) * (q - 1)
```

Then it chooses a small private exponent `d` and computes:

```text
e = d^(-1) mod phi
```

The bad part is that `d` is forced under the Wiener bound:

```python
d_target_bits = int(bits * 0.205)
...
wiener_bound = isqrt(isqrt(N)) // 3
if d >= wiener_bound:
    continue
```

That means the RSA private key is recoverable from only `(N, e)`.

Wiener's attack uses the continued fraction convergents of:

```text
e / N
```

For the correct convergent, the denominator is `d` and the numerator is `k`, where:

```text
e*d - 1 = k*phi(N)
```

So for each convergent `k/d`, I can try:

```text
phi = (e*d - 1) / k
```

Then once I have a candidate `phi`, I can recover `p` and `q` from:

```text
p + q = N - phi + 1
```

because `p` and `q` are the roots of:

```text
x^2 - (p + q)x + N = 0
```

If the discriminant is a perfect square and the roots multiply back to `N`, then the candidate is correct.

## Deriving the AES key

After recovering `d`, this is not done yet because the flag is not RSA-encrypted directly. It is encrypted with AES-GCM.

The key derivation uses three values:

```text
d
S
lambda_n
```

`S` is already leaked in `leakage2`, and after factoring `N` I can compute:

```text
lambda_n = lcm(p - 1, q - 1)
```

There is also a nice sanity check from `leakage3`:

```text
lambda_n mod modulus == lambda_mod
```

The AES key is derived like this:

```python
V_int = long_to_bytes(d)[:16]

H1 = sha256(V_int).digest()
H2 = sha256(long_to_bytes(S)).digest()
H3 = sha256(long_to_bytes(lambda_n)).digest()

IKM = H1 + H2 + H3

key = HKDF(
    algorithm=SHA256,
    length=32,
    salt=b"FastLane-RSA-2024",
    info=b"FastLane-AES-Key",
).derive(IKM)
```

Then AES-GCM decrypts:

```text
encrypted_flag || tag
```

using the provided nonce.

So the whole attack chain is:

```text
(N, e)
  -> Wiener's attack
  -> recover d
  -> recover phi
  -> factor N
  -> compute lambda_n
  -> rebuild AES key
  -> AES-GCM decrypt flag
```

The extra leakage is mostly there to make the challenge look more complicated than it actually is. The real shortcut is just the tiny `d`.

## Solution Script

Here is the final solve script I used. It connects to the service, recovers the RSA private exponent with Wiener's attack, rebuilds the AES key, decrypts the flag, and sends it back to the server.

```python
#!/usr/bin/env python3
import json
import math
import socket
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


HOST = "51.79.140.18"
PORT = 15004


def long_to_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def continued_fraction(a: int, b: int):
    while b:
        q = a // b
        yield q
        a, b = b, a - q * b


def convergents(cf):
    n0, n1 = 0, 1
    d0, d1 = 1, 0

    for a in cf:
        n2 = a * n1 + n0
        d2 = a * d1 + d0

        yield n2, d2

        n0, n1 = n1, n2
        d0, d1 = d1, d2


def wiener_factor(N: int, e: int):
    for k, d in convergents(continued_fraction(e, N)):
        if k == 0:
            continue

        ed_minus_1 = e * d - 1
        if ed_minus_1 % k != 0:
            continue

        phi = ed_minus_1 // k
        if phi <= 0 or phi >= N:
            continue

        s = N - phi + 1
        disc = s * s - 4 * N
        if disc < 0:
            continue

        r = math.isqrt(disc)
        if r * r != disc:
            continue

        if (s + r) % 2 != 0:
            continue

        p = (s + r) // 2
        q = (s - r) // 2

        if p * q == N:
            return d, p, q, phi

    raise ValueError("Wiener attack failed")


def derive_aes_key(d: int, S: int, lambda_n: int) -> bytes:
    V_int = long_to_bytes(d)[:16]

    H1 = hashlib.sha256(V_int).digest()
    H2 = hashlib.sha256(long_to_bytes(S)).digest()
    H3 = hashlib.sha256(long_to_bytes(lambda_n)).digest()

    IKM = H1 + H2 + H3

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"FastLane-RSA-2024",
        info=b"FastLane-AES-Key",
    )

    return hkdf.derive(IKM)


def decrypt_flag(params: dict) -> str:
    N = int(params["N"])
    e = int(params["e"])

    print("[*] Running Wiener's attack...")
    d, p, q, phi = wiener_factor(N, e)

    print(f"[+] Recovered d: {d}")
    print(f"[+] p bits: {p.bit_length()}")
    print(f"[+] q bits: {q.bit_length()}")

    lambda_n = math.lcm(p - 1, q - 1)
    S = int(params["leakage2"]["S"])

    leaked_lambda_mod = int(params["leakage3"]["lambda_mod"])
    leaked_modulus = int(params["leakage3"]["modulus"])

    if lambda_n % leaked_modulus == leaked_lambda_mod:
        print("[+] lambda_n leakage check passed")
    else:
        print("[!] lambda_n leakage check failed, but continuing...")

    key = derive_aes_key(d, S, lambda_n)

    nonce = bytes.fromhex(params["nonce"])
    ct = bytes.fromhex(params["encrypted_flag"])
    tag = bytes.fromhex(params["tag"])

    flag = AESGCM(key).decrypt(nonce, ct + tag, None)
    return flag.decode()


def recv_json(sock: socket.socket) -> dict:
    data = b""

    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break

        data += chunk

        try:
            start = data.index(b"{")
            end = data.rindex(b"}") + 1
            return json.loads(data[start:end].decode())
        except (ValueError, json.JSONDecodeError):
            continue

    raise ValueError("Could not receive valid JSON")


def main():
    with socket.create_connection((HOST, PORT)) as s:
        params = recv_json(s)

        print("[+] Received params")
        flag = decrypt_flag(params)

        print(f"[+] Flag: {flag}")

        s.sendall(flag.encode() + b"\n")

        try:
            response = s.recv(4096).decode(errors="replace")
            print("[+] Server response:")
            print(response)
        except Exception:
            pass


if __name__ == "__main__":
    main()
```

Running it gives:

```text
[+] Received params
[*] Running Wiener's attack...
[+] Recovered d: 5776862812030794711935186665541388499821648528840097136760432240275971510091993491
[+] p bits: 768
[+] q bits: 768
[+] lambda_n leakage check passed
[+] Flag: LYKNCTF{abae6bf0e4e7489f9ec472aa8baa3a03}
[+] Server response:
{"status": "success", "message": "Correct flag!"}
```

## Why this works

RSA is only safe if the private exponent is large enough. Here, `d` is intentionally generated below the Wiener bound, which makes it recoverable from the public key alone.

The leakages are useful for checking that the recovered values are right, but they are not actually needed to break the RSA part. Once Wiener's attack gives `d`, factoring `N` is straightforward because `phi(N)` comes from:

```text
phi = (e*d - 1) / k
```

Then `lambda_n` and the leaked `S` let us reconstruct the exact AES-GCM key. Since AES-GCM verifies the tag, the final decrypt either fails completely or returns the real flag.

So the mistake is not AES-GCM, HKDF, or even the extra leakages. The core bug is using a private RSA exponent small enough that the public key gives it away.
