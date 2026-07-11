---
title: Hash & Dash
date: 2026-07-06
tags:
- crypto
- LYKNCTF
---

- **Challenge:** Hash & Dash
- **Category:** Crypto
- **Flag:** `LYKNCTF{0a419485a0bb4d1bb5b6040b31bc5787}`

---

## My initial read / first impressions

The challenge gives a tiny access-token service. Connecting with netcat gives one valid guest token:

```bash
nc TARGET PORT
```

The service prints something like:

```json
{
  "message": "user=guest&role=viewer",
  "message_hex": "757365723d677565737426726f6c653d766965776572",
  "token": "14c826ab50bd059e9d2cffe4aab56c18b2599e36554d4142687653f7134f3dcc"
}
```

Then it asks us to submit one JSON line:

```text
Submit one JSON line with msg and tag.
>
```

So we get a message, its hex encoding, and a tag. The goal is to submit a new valid token for a message that gives admin access.

The message is just URL-style parameters:

```text
user=guest&role=viewer
```

My first thought was that the token was probably a hash/MAC over the message. Since the tag is 64 hex characters, it looks exactly like a SHA-256 digest.

That made the likely bug pretty clear: if the service is doing something like this:

```python
tag = sha256(secret + message).hexdigest()
```

then it is vulnerable to a SHA-256 length extension attack.

## The Vulnerability

SHA-256 is a Merkle-Damgard hash. That means the digest is basically the internal state after hashing all the padded message blocks.

If a MAC is built like this:

```text
SHA256(secret || message)
```

then knowing the digest for `message` lets us continue hashing more data, as long as we can guess the length of `secret`.

We do not need to know the secret bytes. We only need to guess how long the secret is so we can recreate the exact SHA-256 glue padding for:

```text
secret || original_message
```

Then we can forge a message shaped like:

```text
original_message || glue_padding || attacker_controlled_suffix
```

and compute the valid tag for that longer message.

In this challenge, the original message was:

```text
user=guest&role=viewer
```

I first tried appending:

```text
&role=admin
```

and brute forced possible secret lengths.

## Getting a valid forged token

One small gotcha was that the service gives a fresh token on each connection. My first script hardcoded the token from my original netcat connection, which obviously failed once the server gave me a different token later.

The fix was to connect, parse the current `message_hex` and current `token`, and forge using that token in the same connection.

Brute forcing secret lengths found that `16` was correct:

```text
[+] Trying secret_len=16
{"ok": true, "admin": false, "error": "token valid but no admin grant"}
```

That response is actually really useful. It means the crypto part worked. The server accepted the forged tag, but my appended parameter did not satisfy the admin check.

So the remaining issue was not hashing anymore, it was the message semantics.

`&role=admin` made a valid token, but the server still said no admin. That probably meant the server was checking a separate parameter like `admin=true`, or it parsed the first `role` value and kept `viewer`.

Trying this append worked immediately:

```text
&admin=true
```

The service returned:

```json
{"ok": true, "admin": true, "flag": "LYKNCTF{0a419485a0bb4d1bb5b6040b31bc5787}"}
```

## Solution Script

Here is the final solve script I used. It gets the fresh guest token, performs the SHA-256 length extension attack with the correct secret length, and tries a few likely admin suffixes.

```python
#!/usr/bin/env python3
import socket
import json
import struct
import re

HOST = "replace.host.here"
PORT = 1337

SECRET_LEN = 16

APPENDS = [
    b"&admin=true",
    b"&admin=1",
    b"&is_admin=true",
    b"&is_admin=1",
    b"&role=admin",
    b"&user=admin",
    b"&user=admin&role=admin",
    b"&role=admin&user=admin",
    b"&access=admin",
    b"&grant=admin",
    b"&permission=admin",
    b"&permissions=admin",
    b"&privilege=admin",
    b"&privileges=admin",
    b"&auth=admin",
    b"&role=administrator",
]

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff


def sha256_padding(msg_len):
    bit_len = msg_len * 8
    pad = b"\x80"
    pad += b"\x00" * ((56 - (msg_len + 1) % 64) % 64)
    pad += struct.pack(">Q", bit_len)
    return pad


def sha256_compress(chunk, h):
    w = list(struct.unpack(">16I", chunk)) + [0] * 48

    for i in range(16, 64):
        s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff

    a, b, c, d, e, f, g, hh = h

    for i in range(64):
        S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ ((~e) & g)
        temp1 = (hh + S1 + ch + K[i] + w[i]) & 0xffffffff

        S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xffffffff

        hh = g
        g = f
        f = e
        e = (d + temp1) & 0xffffffff
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xffffffff

    return [
        (h[0] + a) & 0xffffffff,
        (h[1] + b) & 0xffffffff,
        (h[2] + c) & 0xffffffff,
        (h[3] + d) & 0xffffffff,
        (h[4] + e) & 0xffffffff,
        (h[5] + f) & 0xffffffff,
        (h[6] + g) & 0xffffffff,
        (h[7] + hh) & 0xffffffff,
    ]


def sha256_len_ext(old_digest_hex, append_data, total_len_before_append):
    h = list(struct.unpack(">8I", bytes.fromhex(old_digest_hex)))

    new_total_len = total_len_before_append + len(append_data)
    data = append_data + sha256_padding(new_total_len)

    for i in range(0, len(data), 64):
        h = sha256_compress(data[i:i + 64], h)

    return b"".join(struct.pack(">I", x) for x in h).hex()


def recv_until_prompt(s):
    data = b""
    while b"> " not in data:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def parse_banner(data):
    text = data.decode(errors="ignore")
    m = re.search(r"\{.*?\}", text, re.S)
    if not m:
        raise ValueError("Could not find JSON banner")

    obj = json.loads(m.group(0))
    msg = bytes.fromhex(obj["message_hex"])
    token = obj["token"]
    return msg, token, text


def try_append(append_data):
    with socket.create_connection((HOST, PORT), timeout=5) as s:
        banner = recv_until_prompt(s)
        orig_msg, orig_tag, _ = parse_banner(banner)

        glue = sha256_padding(SECRET_LEN + len(orig_msg))
        forged_msg = orig_msg + glue + append_data

        total_len_before_append = SECRET_LEN + len(orig_msg) + len(glue)
        forged_tag = sha256_len_ext(
            orig_tag,
            append_data,
            total_len_before_append,
        )

        payload = json.dumps({
            "msg": forged_msg.hex(),
            "tag": forged_tag,
        }).encode() + b"\n"

        print(f"[+] Trying append={append_data!r}")
        print(f"    forged_msg={forged_msg.hex()}")
        print(f"    forged_tag={forged_tag}")

        s.sendall(payload)
        resp = s.recv(4096)

        decoded = resp.decode(errors="ignore")
        print(decoded)

        return resp, forged_msg, forged_tag


def main():
    for append_data in APPENDS:
        try:
            resp, forged_msg, forged_tag = try_append(append_data)
        except Exception as e:
            print(f"[-] Error with append={append_data!r}: {e}")
            continue

        low = resp.lower()

        if b'"admin": true' in low or b"flag" in low:
            print("[+] SOLVED")
            print("[+] Final JSON:")
            print(json.dumps({
                "msg": forged_msg.hex(),
                "tag": forged_tag,
            }))
            return

        if b'"ok": true' in low:
            print("[*] Token valid, but not admin. Trying next append...")

    print("[-] Tried all append strings. Crypto worked, but none granted admin.")


if __name__ == "__main__":
    main()
```

Running it gave:

```text
[+] Trying append=b'&admin=true'
    forged_msg=757365723d677565737426726f6c653d76696577657280000000000000000000000000000000000000000000000001302661646d696e3d74727565
    forged_tag=8a196e9b327eeb90a916b471d09391ce179e1c27933261ac33b17c7833bfd040
{"ok": true, "admin": true, "flag": "LYKNCTF{0a419485a0bb4d1bb5b6040b31bc5787}"}
```

## Why this works

The service trusted a tag that was probably computed as:

```text
SHA256(secret || msg)
```

That construction is not a safe MAC because SHA-256 lets us continue hashing from an existing digest.

The attack flow was:

```text
valid guest token
    -> guess secret length
    -> recreate SHA-256 glue padding
    -> append &admin=true
    -> continue SHA-256 from the old digest
    -> submit forged msg/tag
    -> admin=true
    -> flag
```

The important detail is that the forged message contains raw SHA-256 padding bytes, so I sent it as hex in the `msg` field instead of trying to send it as a normal string.

The final forged JSON looked like:

```json
{
  "msg": "757365723d677565737426726f6c653d76696577657280000000000000000000000000000000000000000000000001302661646d696e3d74727565",
  "tag": "8a196e9b327eeb90a916b471d09391ce179e1c27933261ac33b17c7833bfd040"
}
```

Once the server decoded that message and verified the tag, it saw `admin=true` and returned the flag.
