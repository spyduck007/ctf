---
title: Cyclic Echo
date: 2026-07-06
tags:
- crypto
- LYKNCTF
---

- **Challenge:** Cyclic Echo
- **Category:** Crypto
- **Flag:** `LYKNCTF{dd8b59e0420b4b82b9a40e21a8bb921e}`

---

## My initial read / first impressions

The challenge description says:

```text
A signal keeps repeating, echoing back on itself in a loop no one can quite explain. Listen closely enough, and the echo gives away where it came from.
```

Connecting to the service gives one big JSON blob:

```bash
nc 51.79.140.18 11684
```

The important parts look like this:

```json
{
  "parameters": {
    "N": 127,
    "q": 4093,
    "q_prime": 4099,
    "leak_modulus": 127,
    "ring": "Z_4093[x]/(x^127 - 1)",
    "df": {"plus": 20, "minus": 19},
    "dg": {"plus": 20, "minus": 20}
  },
  "public_key": {
    "h": [3938, 4035, 2891, 2390, 1408]
  },
  "side_channel": {
    "f": {
      "even_sum_mod_P": 2,
      "odd_sum_mod_P": 126
    },
    "g": {
      "even_sum_mod_P": 0,
      "odd_sum_mod_P": 0
    }
  },
  "encrypted_flag": {
    "salt": "8635d7aaa0ab514b1b237753348fb8c5",
    "nonce": "13fc01d04f40eb248aeb9891",
    "ciphertext": "d475e29343f8248e43e407962e94f500811251bd1f607e1dd377f4e06bc34ca14c04cfff5650fb02b2",
    "tag": "7d19ab995f9f92e5c8ce1922b7b7f5e9"
  }
}
```

At first, this looks like another NTRU-style challenge. We have a cyclic polynomial ring, a public key `h`, secret ternary polynomials `f` and `g`, and a tiny side channel leaking the even and odd sums of both polynomials.

So the natural first thought is:

```text
h = g * f^(-1) mod q
```

and maybe the leak is supposed to help recover `f` and `g`.

But before trying any lattice / meet-in-the-middle pain, I checked the provided generator code to see how the flag encryption key is actually derived.

## Looking at the key derivation

The generator creates the NTRU-ish public key like this:

```python
f_inv = poly_inverse_cyclic([c % Q for c in candidate], N, Q)
h = poly_mul_mod([c % Q for c in g], f_inv, N, Q)
```

So yes, the public key is built from the secret polynomials. But the AES key is not derived from the full `f` and `g`.

Instead, the generator computes this value:

```python
def _algebraic_signature(f, g):
    return sum((i + 1) * f[i] * g[i] for i in range(N)) % Q_PRIME
```

Then it derives the AES key from only that small value:

```python
def _derive_key(s_alg, salt):
    ikm = s_alg.to_bytes(2, "big") + N.to_bytes(2, "big") + Q.to_bytes(2, "big")
    return HKDF(master=ikm, key_len=32, salt=salt, hashmod=SHA256, context=KDF_INFO)
```

The important parameter is:

```text
q_prime = 4099
```

That means `s_alg` can only be one of 4099 possible values.

That is not even close to enough entropy for an AES key. The NTRU part and the side channel are basically a giant cloud of smoke around a tiny brute force.

## The Vulnerability

AES-GCM itself is not broken here. In fact, AES-GCM makes the attack nicer because it has an authentication tag.

For every possible `s_alg`, I can derive the key exactly the same way the generator does:

```python
ikm = s_alg.to_bytes(2, "big") + N.to_bytes(2, "big") + Q.to_bytes(2, "big")
key = HKDF(master=ikm, key_len=32, salt=salt, hashmod=SHA256, context=b"lyknctf-2026")
```

Then I try decrypting:

```python
AESGCM(key).decrypt(nonce, ciphertext + tag, None)
```

If the key is wrong, the GCM tag check fails. If the key is right, it gives the plaintext flag.

So the whole solve is just:

```text
for s_alg in range(4099):
    derive candidate key
    try AES-GCM decrypt
    if tag verifies:
        print the plaintext
```

No need to recover `f`. No need to recover `g`. No need to use the public key or the side channel.

## Solution Script

Here is the final solve script I used. It connects to the service, reads the JSON, brute forces all possible `s_alg` values, and lets AES-GCM tell us when the key is correct.

```python
#!/usr/bin/env python3
import json
import socket
import sys

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


HOST = "51.79.140.18"
PORT = 11684

KDF_INFO = b"lyknctf-2026"


def recv_json(host, port):
    data = b""
    with socket.create_connection((host, port), timeout=10) as s:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk

    text = data.decode(errors="replace").strip()
    return json.loads(text)


def derive_key(s_alg, salt, N, Q):
    ikm = s_alg.to_bytes(2, "big") + N.to_bytes(2, "big") + Q.to_bytes(2, "big")
    return HKDF(
        master=ikm,
        key_len=32,
        salt=salt,
        hashmod=SHA256,
        context=KDF_INFO,
    )


def main():
    if len(sys.argv) == 2:
        # Optional: solve from a saved JSON file
        with open(sys.argv[1], "r") as f:
            inst = json.load(f)
    else:
        inst = recv_json(HOST, PORT)

    params = inst["parameters"]
    enc = inst["encrypted_flag"]

    N = int(params["N"])
    Q = int(params["q"])
    Q_PRIME = int(params["q_prime"])

    salt = bytes.fromhex(enc["salt"])
    nonce = bytes.fromhex(enc["nonce"])
    ciphertext = bytes.fromhex(enc["ciphertext"])
    tag = bytes.fromhex(enc["tag"])

    blob = ciphertext + tag

    print(f"[+] Bruting s_alg in range 0..{Q_PRIME - 1}")

    for s_alg in range(Q_PRIME):
        key = derive_key(s_alg, salt, N, Q)
        aesgcm = AESGCM(key)

        try:
            pt = aesgcm.decrypt(nonce, blob, None)
        except Exception:
            continue

        print(f"[+] Found s_alg = {s_alg}")
        print(f"[+] Plaintext: {pt!r}")

        try:
            print(pt.decode())
        except UnicodeDecodeError:
            pass

        return

    print("[-] No valid key found")


if __name__ == "__main__":
    main()
```

Running it gives:

```text
[+] Bruting s_alg in range 0..4098
[+] Found s_alg = 615
[+] Plaintext: b'LYKNCTF{dd8b59e0420b4b82b9a40e21a8bb921e}'
LYKNCTF{dd8b59e0420b4b82b9a40e21a8bb921e}
```

## Why this works

The challenge tries to look like a secret polynomial recovery problem, but the encrypted flag only depends on this one value:

```text
s_alg mod 4099
```

Since `q_prime` is only 4099, the effective key space is only 4099 candidates.

AES-GCM gives us a perfect check for each candidate because incorrect keys fail tag verification. Once the loop reaches `s_alg = 615`, the tag verifies and the plaintext flag comes out.

So the actual bug is not in the NTRU relation, AES, or HKDF. The bug is that the challenge compresses the secret material down into a tiny 12-bit-ish value before deriving the encryption key.
