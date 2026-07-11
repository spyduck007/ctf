---
title: Cr4ck 2
date: 2026-07-06
tags:
- rev
- LYKNCTF
---

- **Challenge:** Cr4ck 2
- **Category:** Rev
- **Flag:** `LYKNCTF{V1rtu4l_ARX_VM_LLM_h3ll_LYKN2026}`

---

## My initial read / first impressions

The challenge description was just:

```text
Cr4ck Cr4ck Cr4ck
```

We are given a Windows executable:

```text
Activator.exe
```

So this immediately looked like a normal crackme / license checker challenge. I expected some kind of serial input box, a format check, and then either a hardcoded comparison or a small custom checker hidden behind some annoying reversing tricks.

The binary is a native MinGW x64 executable, not a .NET binary, so there was no easy dnSpy-style path here. Also, the flag was not just sitting directly in `strings`.

The UI itself is basically an activator window. The actual interesting part starts after the textbox input is read.

## Finding the flag format check

The first layer is just format validation. The program checks that the input looks like:

```text
LYKNCTF{................................}
```

where the inside is exactly 32 characters.

So the total expected length is:

```text
8 byte prefix + 32 byte body + 1 byte suffix = 41 bytes
```

That is useful because it tells us the checker is only trying to recover / validate 32 unknown bytes. At this point, I knew the real target was not the prefix or suffix. The real work was whatever transform happened to those 32 inner bytes.

## The annoying part: encrypted VM bytecode

After the normal format check, the binary does not just compare the input directly. Instead, it decrypts a small bytecode blob and runs a tiny VM-ish checker.

The bytecode is stored encrypted in `.rdata`. For the provided binary, the useful file offsets were:

```python
text_off = 0x400
text_size = 0x3910
enc_off = 0x4220
const_off = 0x43e8
```

The decryption key is derived from the `.text` section hash, an anti-debug byte, and the hardcoded string `7KYL`:

```python
text_hash = sha256(.text)
seed = sha256(text_hash || anti_debug_byte || b"7KYL")
```

Then each 32-byte block of VM bytecode is XORed with:

```python
sha256(seed || block_index_as_4_bytes)
```

The anti-debug part is a little trap. If the program thinks it is being debugged, the byte changes and the VM decrypts wrong. For the normal no-debugger path, the byte is just:

```text
00
```

So the useful seed is:

```python
seed = sha256(text_hash + b"\x00" + b"7KYL")
```

Once decrypted, the VM was not actually that huge. It applies 32 rounds of ARX-style operations over the 32-byte flag body, viewed as 8 little-endian 32-bit integers.

## Understanding the ARX check

The checker takes the 32 inner flag bytes and splits them like this:

```python
regs = list(struct.unpack("<8I", body))
```

Then it runs 32 rounds using rotates, XORs, and additions. The important constants are:

```python
rots = [7, 9, 13, 18, 3, 11, 17, 5]
delta = 0x9e3779b9
```

Each round uses a key-like value:

```python
k = 0x1badc0de + round_no * delta
```

After all 32 rounds, the final 8 words are compared against constants stored in `.rdata` at `const_off`.

At first this looks annoying because brute forcing 32 bytes is obviously impossible. But the transform is reversible. Since it is all ARX operations, we can just start from the final constants and run the rounds backwards.

The inverse logic is:

```python
old[7] = ror(new[7] ^ new[0], rots[7]) - k

for i in range(6, -1, -1):
    old[i] = ror(new[i] ^ old[i + 1], rots[i]) - k
```

So instead of guessing the flag, we decrypt the VM, read the final target state, invert all 32 rounds, and the original input words fall out directly.

## Solution Script

Here is the final solve script I used.

```python
#!/usr/bin/env python3
import hashlib
import struct
from pathlib import Path

EXE = Path("Activator.exe")
blob = EXE.read_bytes()

# PE layout from Activator.exe
text_off = 0x400
text_size = 0x3910
enc_off = 0x4220          # VA 0x140006220 in .rdata
const_off = 0x43e8        # VA 0x1400063e8 in .rdata

# The VM bytecode is XOR-encrypted with a stream derived from:
#   sha256(sha256(.text) || anti_debug_flags || b"7KYL")
text_hash = hashlib.sha256(blob[text_off:text_off + text_size]).digest()
seed = hashlib.sha256(text_hash + b"\x00" + b"7KYL").digest()

enc = blob[enc_off:enc_off + 0xc0]
vm = bytearray()

for block in range(6):
    key = hashlib.sha256(seed + bytes([block, 0, 0, 0])).digest()
    vm += bytes(a ^ b for a, b in zip(enc[32 * block:32 * (block + 1)], key))

# The decrypted VM applies 32 rounds of ARX over 8 little-endian words.
# Its final constants are stored at const_off; invert the rounds to recover input words.
regs = list(struct.unpack("<8I", blob[const_off:const_off + 32]))

rots = [7, 9, 13, 18, 3, 11, 17, 5]
delta = 0x9e3779b9


def ror(x, n):
    return ((x >> n) | ((x << (32 - n)) & 0xffffffff)) & 0xffffffff


for round_no in range(31, -1, -1):
    k = (0x1badc0de + round_no * delta) & 0xffffffff

    new = regs[:]
    old = [0] * 8

    old[7] = (ror(new[7] ^ new[0], rots[7]) - k) & 0xffffffff

    for i in range(6, -1, -1):
        old[i] = (ror(new[i] ^ old[i + 1], rots[i]) - k) & 0xffffffff

    regs = old

body = b"".join(struct.pack("<I", x) for x in regs).decode()
flag = f"LYKNCTF{{{body}}}"
print(flag)
```

Running it prints:

```text
LYKNCTF{V1rtu4l_ARX_VM_LLM_h3ll_LYKN2026}
```

## Why this works

The challenge tries to hide the real checker behind an encrypted VM and an anti-debug-dependent key. That makes the binary look more annoying than it actually is.

The important observations were:

1. The input format fixes the unknown body to exactly 32 bytes.
2. The VM bytecode decrypts correctly when the anti-debug byte is `0x00`.
3. The 32-byte body is treated as 8 little-endian `uint32` values.
4. The VM transform is ARX-based, so every operation is reversible.
5. The final target state is stored in the binary, so we can invert the rounds instead of brute forcing anything.

So the full solve path is:

```text
Activator.exe
    -> find format check
    -> locate encrypted VM blob
    -> derive VM decryption key from sha256(.text), anti-debug byte, and "7KYL"
    -> decrypt bytecode
    -> identify 32 ARX rounds over 8 words
    -> read final target constants
    -> run ARX rounds backwards
    -> recover the 32-byte flag body
```

The VM/anti-debug layer is mostly there to make static reversing feel gross, but once the round function is copied out, the solve is clean. No brute force needed.

## Flag

```text
LYKNCTF{V1rtu4l_ARX_VM_LLM_h3ll_LYKN2026}
```
