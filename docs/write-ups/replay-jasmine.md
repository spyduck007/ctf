---
title: Replay-Jasmine?
date: 2026-07-06
tags:
- crypto
- LYKNCTF
---

- **Challenge:** Replay-Jasmine?
- **Category:** Crypto
- **Flag:** `LYKNCTF{Connect_The_World}`

---

## My initial read / first impressions

The challenge description says:

```text
Yesterday I watched a MV but I forgot it. I look up history but all crypted. Can you decrypt it?
```

We are given two files:

* `chall.json`
* `aux.py`

At first, `aux.py` looks like the scary part because it defines a custom cipher called `Shiina256PIGE`. Usually custom crypto means pain, but this one also has authentication, so randomly poking at the ciphertext is not useful. If the MAC does not verify, decryption just stops.

So the real question is not "how do I break this block mode?"

The real question is:

```text
Where does the 32-byte key come from?
```

Looking at `chall.json`, there are a few very suspicious fields:

```json
{
  "Alcginlcgchall": [[...]],
  "donttimebabybob": [...],
  "timeforR": [[...]],
  "c": [...],
  "kdf": {
    "alg": "i_love_ltc_coin",
    "subset_sum_problem?": 16384,
    "r": 8,
    "p": 4000,
    "eww_too_salty": "736869696e612d6374662d32303235",
    "dklen": 32
  },
  "finally": "..."
}
```

The names are goofy, but the structure is not random. There are two matrix/vector pairs, a KDF config, and then one final encrypted blob.

The KDF name is the hint: Litecoin uses `scrypt`, so `i_love_ltc_coin` is basically screaming that the recovered password needs to go through `hashlib.scrypt()`.

## Looking at the equations

The first pair is:

```text
Alcginlcgchall: 32 x 20 matrix mod 769
donttimebabybob: length 32 vector mod 769
```

The second pair is:

```text
timeforR: 28 x 18 matrix mod 503
c: length 28 vector mod 503
```

This looked like two small LWE-style systems:

```text
b = A*s + e mod q
```

where:

* `A` is public
* `b` is public
* `s` is a small secret vector
* `e` is a small error/noise vector
* `q` is the modulus

The dimensions are small enough that this is very recoverable with a lattice attack. The important giveaway is that the values are modulo `769` and `503`, but the hidden vectors are tiny. That means the correct solution gives a very short vector compared to random modular garbage.

## Recovering the small secrets

I solved each matrix/vector pair as a bounded LWE instance. The goal was to find small `s` and small `e` such that:

```text
A*s + e = b mod q
```

For the first system, the recovered secret was:

```python
s1 = [-1, 3, 3, 1, 2, 3, 2, 3, 2, 0, 3, -1, 3, 0, 3, 2, -1, -2, -2, 1]
```

For the second system, the recovered secret was:

```python
s2 = [-2, -2, 1, -1, -2, 2, 2, 0, -1, -2, -2, 0, 1, 0, -1, 0, -1, 2]
```

I also checked the residuals to make sure this was not just some random vector that happened to fit. For both systems, `b - A*s mod q` turns into tiny signed values, which is exactly what we expect from the noise term.

So at this point the lattice part was done. The only remaining problem was the extremely annoying CTF part: figuring out exactly how these two recovered vectors were serialized into the KDF password.

## The annoying serialization detail

The KDF parameters are:

```python
N = 16384
r = 8
p = 4000
dklen = 32
salt = bytes.fromhex("736869696e612d6374662d32303235")
```

The salt decodes to:

```text
shiina-ctf-2025
```

Because `p = 4000`, every wrong password guess is slow. So this is a pretty rude place to hide a packing detail.

The working serialization was not ASCII, CSV, JSON, bytes shifted into `0..6`, or nibble packing. The challenge packs the recovered coefficients as signed 32-bit little-endian integers:

```python
password = b"".join(struct.pack("<i", x) for x in (s1 + s2))
```

That means each small value like `-1`, `0`, `1`, `2`, `3` becomes four bytes.

For example:

```text
-1 -> ff ff ff ff
 3 -> 03 00 00 00
```

Once I used that password, `scrypt` gave the correct 32-byte master key, and the `Shiina256PIGE` MAC verified.

## Decrypting the final ciphertext

The final ciphertext is stored in `finally` as hex. After deriving the master key, the rest is just using the provided cipher:

```python
cipher = Shiina256PIGE(master_key)
plaintext = cipher.decrypt(bytes.fromhex(data["finally"]))
```

The plaintext was:

```text
LYKNCTF{Connect_The_World}
```

So the whole challenge chain is:

```text
chall.json
  -> recover two tiny LWE secrets
  -> concatenate s1 + s2
  -> pack each coefficient as signed little-endian int32
  -> scrypt(password, salt="shiina-ctf-2025", N=16384, r=8, p=4000)
  -> decrypt finally with Shiina256PIGE
  -> flag
```

## Solution Script

This is the final solve script. It assumes `aux.py` and `chall.json` are in the same directory.

```python
#!/usr/bin/env python3
import hashlib
import json
import struct
import re

from aux import Shiina256PIGE


s1 = [-1, 3, 3, 1, 2, 3, 2, 3, 2, 0, 3, -1, 3, 0, 3, 2, -1, -2, -2, 1]
s2 = [-2, -2, 1, -1, -2, 2, 2, 0, -1, -2, -2, 0, 1, 0, -1, 0, -1, 2]


with open("chall.json", "r") as f:
    data = json.load(f)

kdf = data["kdf"]

password = b"".join(struct.pack("<i", x) for x in (s1 + s2))
salt = bytes.fromhex(kdf["eww_too_salty"])

master_key = hashlib.scrypt(
    password=password,
    salt=salt,
    n=kdf["subset_sum_problem?"],
    r=kdf["r"],
    p=kdf["p"],
    dklen=kdf["dklen"],
)

cipher = Shiina256PIGE(master_key)
plaintext = cipher.decrypt(bytes.fromhex(data["finally"]))

print(plaintext.decode(errors="replace"))

m = re.search(rb"LYKNCTF\{[^}]+\}", plaintext)
if m:
    print("[+] FLAG:", m.group(0).decode())
```

Running it gives:

```text
LYKNCTF{Connect_The_World}
[+] FLAG: LYKNCTF{Connect_The_World}
```
