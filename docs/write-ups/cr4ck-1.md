---
title: Cr4ck 1
date: 2026-07-06
tags:
- rev
- LYKNCTF
---

- **Challenge:** Cr4ck 1
- **Category:** Rev
- **Flag:** `LYKNCTF{k3yg3n_h3ll_s3lfh4sh_4ntidbg_h1dd3n_us3r_2026}`

---

## My initial read / first impressions

The challenge description was just:

```text
Cr4ck Cr4ck Cr4ck
```

We are given a Windows executable:

```text
KeygenMe.exe
```

So this looked like the first part of the same crackme/keygenme series as **Cr4ck 2** and **Cr4ck 3**. I expected a username box, a license box, and then some custom serial generation logic instead of the flag just being hardcoded somewhere obvious.

The binary is a native Windows executable, not a .NET program, so there was no easy dnSpy path. Also, `strings` did not directly give the flag. The useful stuff was hidden behind a keygen-style flow:

```text
username -> generated license -> flag decrypt key
```

The UI checks a username and license pair. If they are correct, it decrypts and shows the flag.

## Finding the username

The first important thing was that the username was not typed by the user randomly. The binary has a hidden expected username, but it does not store it directly as a normal string.

There is an RC4-looking setup function around `0x1400014d0`. It initializes a 256-byte S-box and runs a KSA-like shuffle using this embedded key:

```text
L0i_Y3u_Kh0_N0i
```

After that, another function around `0x140001f10` uses values from the shuffled S-box to recover the account name. The first 8 bytes are recovered by building a qword from selected S-box entries and XORing it with a stored qword. The remaining bytes are recovered by XORing another small encrypted array with S-box values.

Once copied out, the recovered username was:

```text
th3_LYKN_v3nd0r
```

That already tells us this is not just a normal serial checker where any username works. The challenge has one intended hidden username, and the correct license is generated from that username.

## Rebuilding the license generator

The license checker uppercases the entered license before comparing it, so the final key has to match the generated key case-insensitively.

The generator takes the username and an anti-debug byte. For the normal path, where the program is not being debugged, that byte is:

```text
00
```

The function around `0x140001660` turns the username into a 16-byte seed. Internally, it keeps four 32-bit state values and repeatedly mixes in S-box lookups based on the username bytes. The mixing uses rotates, XORs, additions, and the constant:

```text
0x9e3779b1
```

After that, the function around `0x1400017b0` turns the 16-byte seed into five 16-bit license groups. The first four groups come from pieces of the generated seed, and the fifth group is a checksum-style group based on the earlier groups and one more seed word.

The format is:

```text
XXXX-XXXX-XXXX-XXXX-XXXX
```

For the recovered username and the no-debugger anti-debug byte, the license becomes:

```text
7211-57C4-CD96-CC26-5B67
```

## The final flag decrypt

At this point, I had a valid username and license, but the flag still was not sitting directly in plaintext. The program decrypts the flag from an encrypted blob in `.rdata`.

The decryption key is based on:

```text
username || 0x1f || uppercase_license || 0x1f || sha256(.text) || anti_debug_byte
```

That whole blob is hashed with SHA-256. Then the program expands it into a stream by hashing:

```text
sha256(master || block_index)
```

and XORs that stream against the encrypted flag bytes.

The `.text` hash is important because it means the vault key is tied to the exact binary. The anti-debug byte is also important because if the debug path is taken, the seed/license/flag key changes and everything decrypts wrong.

For the normal path, the anti-debug byte is `0`, so the correct values are:

```text
username: th3_LYKN_v3nd0r
license : 7211-57C4-CD96-CC26-5B67
```

Using those, the encrypted flag decrypts cleanly.

## Solution Script

Here is the final solve script I used.

```python
#!/usr/bin/env python3
from pathlib import Path
import struct
import hashlib

EXE = Path("KeygenMe.exe")
b = EXE.read_bytes()

RDATA_VA = 0x140006000
RDATA_OFF = 0x4200


def rdata(va, n):
    off = RDATA_OFF + (va - RDATA_VA)
    return b[off:off + n]


alphabet = rdata(0x140006230, 16)
ksa_key = rdata(0x140006248, 15)
account_xor = rdata(0x140006260, 15)
enc_flag = rdata(0x140006280, 0x60)
account_qword_xor = rdata(0x1400063f0, 8)


def rol32(x, n):
    x &= 0xffffffff
    return ((x << n) | (x >> (32 - n))) & 0xffffffff


def init_sbox():
    # Function 0x1400014d0: 0..255 init + RC4-like KSA.
    s = list(range(256))

    j = (s[0] + 0x4c) & 0xff
    s[0], s[j] = s[j], s[0]

    for i in range(1, 256):
        j = (s[i] + ksa_key[i % 15] + j) & 0xff
        s[i], s[j] = s[j], s[i]

    return s


S = init_sbox()


def recover_username():
    # Function 0x140001f10. The S-box lives at stack+0x20,
    # so these stack offsets become S-box indexes minus 0x20.
    idx = [0x42, 0x3d, 0x38, 0x33, 0x2e, 0x29, 0x24, 0x1f]

    v = 0
    for i in idx:
        v = ((v << 8) | S[i]) & 0xffffffffffffffff

    first = (int.from_bytes(account_qword_xor, "little") ^ v).to_bytes(8, "little")
    tail = bytes(account_xor[i] ^ S[0x47 + 5 * (i - 8)] for i in range(8, 15))

    return first + tail


def seed16(username, anti_debug=0):
    # Function 0x140001660: custom 16-byte seed from username + anti-debug byte.
    r12 = 0
    edi = 0xa5a5f00d
    r8 = ((anti_debug & 0xff) * 0x01010101) & 0xffffffff
    r8 ^= 0x4c594b4e
    r9 = 0xae054fb9
    r11 = 0x43544632

    while True:
        for ch in username:
            r10 = S[(ch + r12) & 0xff]
            old_r11, old_r9, old_edi = r11, r9, edi

            r8 = (rol32(r8 ^ r10, 5) + old_r11) & 0xffffffff
            r11 = (rol32((r10 + old_r11) & 0xffffffff, 11) ^ old_r9) & 0xffffffff
            r9 = (rol32(((r10 * 0x9e3779b1) & 0xffffffff) ^ old_r9, 17) + old_edi) & 0xffffffff
            edi = (rol32((S[r8 & 0xff] + old_edi) & 0xffffffff, 3) ^ r8) & 0xffffffff

        r12 += 7
        if r12 == 21:
            break

    for _ in range(4):
        r8 = (r8 + edi) & 0xffffffff
        r11 = (r11 ^ rol32(r8, 7)) & 0xffffffff
        r9 = (r9 + r11) & 0xffffffff
        edi = (edi ^ rol32(r9, 13)) & 0xffffffff

    return struct.pack("<IIII", r8, r11, r9, edi)


def make_license(username, anti_debug=0):
    # Function 0x1400017b0: turn seed into 5 groups of 4 hex chars.
    d0, d1, d2, d3 = struct.unpack("<IIII", seed16(username, anti_debug))

    parts = [
        (d0 >> 16) & 0xffff,
        (d0 ^ d1) & 0xffff,
        (d1 >> 16) & 0xffff,
        (d3 ^ d2) & 0xffff,
        0,
    ]

    parts[4] = ((parts[0] + parts[1] + parts[2] + parts[3]) ^ (d2 >> 16)) & 0xffff

    groups = []
    for p in parts:
        groups.append("".join(chr(alphabet[(p >> shift) & 0xf]) for shift in (12, 8, 4, 0)))

    return "-".join(groups).encode()


def text_section_bytes():
    # The vault key uses SHA256(.text) with IMAGE_SECTION_HEADER.VirtualSize.
    pe = struct.unpack_from("<I", b, 0x3c)[0]
    nsects = struct.unpack_from("<H", b, pe + 6)[0]
    opt_size = struct.unpack_from("<H", b, pe + 20)[0]
    section_table = pe + 24 + opt_size

    for i in range(nsects):
        off = section_table + i * 40
        name = b[off:off + 8].split(b"\0")[0]
        virtual_size, _, raw_size, raw_ptr = struct.unpack_from("<IIII", b, off + 8)

        if name == b".text":
            raw = b[raw_ptr:raw_ptr + min(raw_size, virtual_size)]
            return raw + b"\0" * (virtual_size - len(raw))

    raise RuntimeError("missing .text")


def decrypt_flag(username, license_key, anti_debug=0):
    h_text = hashlib.sha256(text_section_bytes()).digest()

    master = hashlib.sha256(
        username
        + b"\x1f"
        + license_key.upper()
        + b"\x1f"
        + h_text
        + bytes([anti_debug & 0xff])
    ).digest()

    stream = b"".join(hashlib.sha256(master + struct.pack("<I", i)).digest() for i in range(3))
    plaintext = bytes(a ^ c for a, c in zip(enc_flag, stream))

    return plaintext.split(b"\0", 1)[0]


if __name__ == "__main__":
    username = recover_username()
    license_key = make_license(username, anti_debug=0)
    flag = decrypt_flag(username, license_key, anti_debug=0)

    print("username:", username.decode())
    print("license :", license_key.decode())
    print("flag    :", flag.decode())
```

Running it prints:

```text
username: th3_LYKN_v3nd0r
license : 7211-57C4-CD96-CC26-5B67
flag    : LYKNCTF{k3yg3n_h3ll_s3lfh4sh_4ntidbg_h1dd3n_us3r_2026}
```

## Why this works

The challenge is basically a keygenme with three annoying layers stacked on top of each other:

1. The real username is hidden through an RC4-like S-box trick.
2. The license is generated from that username and an anti-debug byte.
3. The flag is encrypted with a key that depends on the username, the license, the `.text` hash, and the anti-debug byte.

The anti-debug piece is the small trap. If the binary thinks it is being debugged, the byte is different, so the generated license and final flag decryption key are both wrong. For the intended clean path, the anti-debug byte is `0x00`.

So the full solve path is:

```text
KeygenMe.exe
    -> find RC4-like S-box setup
    -> recover hidden username
    -> rebuild seed/license generator
    -> use anti-debug byte 0x00
    -> generate valid license
    -> hash exact .text section
    -> derive flag stream
    -> XOR encrypted flag blob
    -> flag
```

The main thing was not trying to brute force the license. Once the username recovery and license generator were copied out, the correct key pair came out directly, and that pair was enough to decrypt the flag.

## Flag

```text
LYKNCTF{k3yg3n_h3ll_s3lfh4sh_4ntidbg_h1dd3n_us3r_2026}
```
