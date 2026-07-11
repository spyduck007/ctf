---
title: Sleepless Machine
date: 2026-07-06
tags:
- crypto
- LYKNCTF
---

- **Challenge:** Sleepless Machine
- **Category:** Crypto
- **Flag:** `LYKNCTF{ed80df9d3af34868a4cb46b937c9fbf3}`

---

## My initial read / first impressions

The challenge description says:

```text
An old machine keeps running day and night in a forgotten bunker, broadcasting the same unchanging sequence. No one remembers what it was built for.
```

Connecting to the service gives one big JSON blob:

```bash
nc 51.79.140.18 18437
```

The important parts are:

```json
{
  "ring": "Z_4093[x]/(x^127 - 1)",
  "parameters": {
    "N": 127,
    "q": 4093,
    "p": 3,
    "q_prime": 1000003
  },
  "public_key": {
    "h": [2469, 834, 2071, 1449, 1807, 859, 995, 3756, 3175]
  },
  "leakage": {
    "f_even_sum": -6,
    "f_odd_sum": -3,
    "g_even_sum": -10,
    "g_odd_sum": 9
  },
  "encrypted_flag": {
    "nonce": "a264b97b0d126a344506a1612a82113e",
    "ciphertext": "f7f89f1f6b2ea2852b50126708d0e1e38640bfaeaf1dc3037567ef314284e9cabd2e33f23b0e6de9cd",
    "tag": "0c00627796c8c423dd49a3df0541451b"
  }
}
```

At first this looks like an NTRU-style challenge. We get a public key `h`, the ring is modulo `x^127 - 1`, and the secret polynomials are named `f` and `g`.

So my first thought was that I would need to recover `f` and `g` from the NTRU relation:

```text
h = g * f^(-1) mod q
```

The leakage gives the even and odd sums of both secret polynomials, so it feels like the intended path might be some lattice / constrained ternary recovery thing.

But before doing anything painful, I checked how the encrypted flag key is actually derived.

## Looking at the key derivation

The generator computes the public key like this:

```python
f_inv = invert_mod_q(f, N, Q)
h = poly_mul_cyclic(g, f_inv, N, Q)
```

Then it computes a value called `s_alg`:

```python
s_alg = weighted_trace(f, g, N, Q_PRIME)
key = _derive_key(s_alg, N, Q, Q_PRIME)
```

The AES key is not derived from all of `f` and `g`. It is derived only from `s_alg`.

The `weighted_trace` function is:

```python
def weighted_trace(f, g, N, q_prime):
    fg = poly_mul_cyclic(f, g, N, q_prime)
    return sum((i + 1) * c for i, c in enumerate(fg)) % q_prime
```

That last `% q_prime` is the whole bug.

The parameter from the server is:

```text
q_prime = 1000003
```

So `s_alg` can only be one of about one million possible values.

That is tiny for a key search.

## The Vulnerability

AES itself is not broken here. AES-GCM is actually really useful for us because it verifies the authentication tag.

For each possible `s_alg`, I can derive the candidate key exactly the same way the challenge does:

```python
ikm = (
    s_alg.to_bytes(4, "big")
    + N.to_bytes(2, "big")
    + q.to_bytes(2, "big")
    + q_prime.to_bytes(4, "big")
)
```

Then I run HKDF-SHA256 with:

```text
salt = str(N).encode()
context = b"lyknctf-2026"
```

and try to decrypt the ciphertext with AES-GCM.

If the key is wrong, AES-GCM tag verification fails. If the key is right, it returns the plaintext flag.

So we do not actually need to solve NTRU at all. The public key and leakage are mostly a distraction. The real attack is just:

```text
for s_alg in range(1000003):
    derive AES key
    try AES-GCM decrypt
    if tag verifies:
        print flag
```

A million AES-GCM attempts is completely reasonable locally.

## Solution Script

Here is the final solve script I used. It connects to the service, reads the JSON instance, brute forces `s_alg`, and lets AES-GCM authentication tell us when the key is correct.

```python
#!/usr/bin/env python3
import json
import socket
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "51.79.140.18"
PORT = 18437

KDF_INFO = b"lyknctf-2026"


def recv_json(host, port):
    s = socket.create_connection((host, port))
    data = b""

    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk

    s.close()
    return json.loads(data.decode())


def hkdf_sha256(master, salt, info, length=32):
    # Equivalent to Crypto.Protocol.KDF.HKDF(..., hashmod=SHA256, context=info)
    prk = hmac.new(salt, master, hashlib.sha256).digest()

    out = b""
    t = b""
    counter = 1

    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1

    return out[:length]


def derive_key(s_alg, N, q, q_prime):
    ikm = (
        s_alg.to_bytes(4, "big")
        + N.to_bytes(2, "big")
        + q.to_bytes(2, "big")
        + q_prime.to_bytes(4, "big")
    )

    return hkdf_sha256(
        master=ikm,
        salt=str(N).encode(),
        info=KDF_INFO,
        length=32,
    )


def main():
    inst = recv_json(HOST, PORT)

    params = inst["parameters"]
    N = params["N"]
    q = params["q"]
    q_prime = params["q_prime"]

    enc = inst["encrypted_flag"]
    nonce = bytes.fromhex(enc["nonce"])
    ciphertext = bytes.fromhex(enc["ciphertext"])
    tag = bytes.fromhex(enc["tag"])

    data = ciphertext + tag

    print(f"[+] Bruting s_alg in range 0..{q_prime - 1}")

    for s_alg in range(q_prime):
        key = derive_key(s_alg, N, q, q_prime)

        try:
            plaintext = AESGCM(key).decrypt(nonce, data, None)
        except Exception:
            continue

        print(f"[+] Found s_alg = {s_alg}")
        print(plaintext.decode())
        return

    print("[-] No valid key found")


if __name__ == "__main__":
    main()
```

Running it gives:

```text
[+] Bruting s_alg in range 0..1000002
[+] Found s_alg = 998318
LYKNCTF{ed80df9d3af34868a4cb46b937c9fbf3}
```

## Why this works

The challenge makes the cryptography look like an NTRU recovery problem, but the encrypted flag only depends on a small derived value:

```text
s_alg mod 1000003
```

Since `q_prime` is only about one million, the AES key space for the flag is effectively only one million candidates.

AES-GCM then gives a perfect success check because a wrong key almost certainly fails tag verification. Once the correct `s_alg` is reached, the tag verifies and the plaintext flag comes out.

So the actual bug is not in AES or HKDF. The bug is that the secret used for key derivation has way too little entropy.
