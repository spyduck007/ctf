---
title: Whispering
date: 2026-07-06
tags:
- crypto
- LYKNCTF
---

- **Challenge:** Whispering
- **Category:** Crypto
- **Flag:** `LYKNCTF{bbabc969e93143a1addd90f8adfe6c80}`

---

## My initial read / first impressions

The challenge description says:

```text
Every basis leaves a whisper behind — if you listen to the right coordinates.
```

Opening the site just gives the available endpoints:

```bash
curl http://TARGET/
```

```json
{
  "challenge": "Whispering",
  "endpoints": {
    "/public.json": "lyknctf",
    "/side_channel.json": "lyknctf"
  }
}
```

So there are only two real files to look at.

`/public.json` gives an NTRU-looking public key and the encrypted flag:

```json
{
  "parameters": {
    "N": 127,
    "p": 3,
    "q": 2048,
    "q_prime": 2053,
    "ring": "Z_2048[x]/(x^127 - 1)"
  },
  "public_key": {
    "h": [945, 1615, 1091, 1922, 133]
  },
  "encrypted_flag": {
    "ciphertext": "07c8020e9184f0bb921122f82a036d50...",
    "iv": "9f938d4b1e7c9c7dfaf1a729bce274e1",
    "salt": "lyknctf-2026"
  }
}
```

`/side_channel.json` gives the "whisper" part:

```json
{
  "constraint_modulus": 127,
  "constraints": {
    "f_even_sum_mod_127": 4,
    "f_odd_sum_mod_127": 116,
    "g_even_sum_mod_127": 122,
    "g_odd_sum_mod_127": 124
  }
}
```

At first this looks like I might need to do some NTRU private key recovery. We have a public key `h`, secret ternary polynomials `f` and `g`, and some leaked modular sums. That sounds like lattice bait.

But the important question is not really "can I recover all of `f` and `g`?" The important question is "what does the AES key actually depend on?"

## Looking at the key derivation

The server computes the public key in the usual NTRU-ish way:

```text
h = g * f^(-1) mod q
```

Then it computes an algebraic signature:

```python
fg_product = poly_mult_mod(f, g, q_prime)
trace = sum(fg_product) % q_prime
```

and derives the AES key from only that `trace` value.

That is the mistake.

For cyclic polynomial multiplication, the sum of all coefficients of the product is just the product of the sums:

```text
sum(f * g) = sum(f) * sum(g)
```

So the AES key does not depend on the full secret polynomials. It only depends on:

```text
V = sum(f) * sum(g) mod 2053
```

The side channel leaks the even and odd sums of both `f` and `g` modulo `127`, which is enough to recover the actual small signed sums.

## Using the side channel

The polynomials have `N = 127` coefficients, each in:

```text
{-1, 0, 1}
```

There are 64 even indices and 63 odd indices.

So the real even sum has to be in:

```text
[-64, 64]
```

and the real odd sum has to be in:

```text
[-63, 63]
```

That makes the modular leaks basically unique, because the range is tiny.

For this instance:

```text
f_even_sum_mod_127 = 4    ->  f_even = 4
f_odd_sum_mod_127  = 116  ->  f_odd  = -11

g_even_sum_mod_127 = 122  ->  g_even = -5
g_odd_sum_mod_127  = 124  ->  g_odd  = -3
```

So:

```text
sum(f) = 4 + (-11) = -7
sum(g) = -5 + (-3) = -8
```

Then the algebraic signature is:

```text
V = (-7 * -8) mod 2053
V = 56
```

Once I have `V`, I can derive the AES key exactly like the server does and decrypt the flag.

## The Vulnerability

The vulnerability is that the encrypted flag key is derived from a value that collapses the secret polynomials down to one tiny coordinate: the sum of the cyclic product.

The challenge looks like an NTRU problem, but we never need to recover `f`, `g`, or even use the public key `h`.

The side-channel leakage gives enough information to recover `sum(f)` and `sum(g)`, and because:

```text
sum(f * g) = sum(f) * sum(g)
```

we can recover the exact AES key material.

So the full attack is:

```text
read public.json
read side_channel.json
recover signed even/odd sums from residues mod 127
compute sum(f), sum(g)
compute V = sum(f) * sum(g) mod q_prime
derive HKDF key
decrypt AES-CBC ciphertext
```

No lattice needed, thankfully.

## Solution Script

Here is the final solve script I used. It grabs the two JSON endpoints, reconstructs the possible signed sums from the modular leaks, derives candidate keys, and stops when the decrypted plaintext contains the flag.

```python
#!/usr/bin/env python3
import json
import urllib.request
from itertools import product

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.Padding import unpad


BASE = "http://TARGET"


def get_json(path):
    with urllib.request.urlopen(BASE + path) as r:
        return json.loads(r.read().decode())


def signed_sum_candidates(residue, modulus, count):
    return [s for s in range(-count, count + 1) if s % modulus == residue % modulus]


def decrypt_flag(public, side):
    params = public["parameters"]
    enc = public["encrypted_flag"]
    cons = side["constraints"]

    N = params["N"]
    q = params["q"]
    q_prime = params["q_prime"]
    salt = enc["salt"]

    even_count = (N + 1) // 2
    odd_count = N // 2
    constraint_modulus = side["constraint_modulus"]

    f_even = signed_sum_candidates(cons["f_even_sum_mod_127"], constraint_modulus, even_count)
    f_odd = signed_sum_candidates(cons["f_odd_sum_mod_127"], constraint_modulus, odd_count)
    g_even = signed_sum_candidates(cons["g_even_sum_mod_127"], constraint_modulus, even_count)
    g_odd = signed_sum_candidates(cons["g_odd_sum_mod_127"], constraint_modulus, odd_count)

    print("[+] candidates:")
    print("    f_even =", f_even)
    print("    f_odd  =", f_odd)
    print("    g_even =", g_even)
    print("    g_odd  =", g_odd)

    ct = bytes.fromhex(enc["ciphertext"])
    iv = bytes.fromhex(enc["iv"])

    for fe, fo, ge, go in product(f_even, f_odd, g_even, g_odd):
        sum_f = fe + fo
        sum_g = ge + go
        V = (sum_f * sum_g) % q_prime

        ikm = (
            V.to_bytes(4, "big")
            + N.to_bytes(2, "big")
            + q.to_bytes(2, "big")
            + salt.encode()
        )

        key = HKDF(
            master=ikm,
            key_len=32,
            salt=str(N).encode(),
            hashmod=SHA256,
        )

        try:
            pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), AES.block_size)
            text = pt.decode()
        except Exception:
            continue

        if "LYKNCTF{" in text:
            print("[+] recovered V =", V)
            print("[+] sum_f =", sum_f)
            print("[+] sum_g =", sum_g)
            print("[+] flag =", text)
            return text

    raise RuntimeError("Flag not found")


def main():
    public = get_json("/public.json")
    side = get_json("/side_channel.json")
    decrypt_flag(public, side)


if __name__ == "__main__":
    main()
```

Running it gives:

```text
[+] candidates:
    f_even = [4]
    f_odd  = [-11]
    g_even = [-5]
    g_odd  = [-3]
[+] recovered V = 56
[+] sum_f = -7
[+] sum_g = -8
[+] flag = LYKNCTF{bbabc969e93143a1addd90f8adfe6c80}
```

## Why this works

The whole trick is that evaluating a polynomial at `x = 1` gives the sum of its coefficients.

For any two cyclic polynomials:

```text
(f * g)(1) = f(1) * g(1)
```

That means:

```text
sum(f * g) = sum(f) * sum(g)
```

The server uses `sum(f * g) mod q_prime` as the secret value for the AES key derivation. Since the side channel leaks the even and odd coefficient sums modulo `127`, and those sums are naturally small, the actual signed sums are easy to recover.

So the challenge title is pretty literal: every basis leaves a whisper behind, and the right coordinate is just the `x = 1` coordinate.
