---
title: The Broken Time Capsule
date: 2026-11-20
tags:
- rev
- WolvCTF-2026
---

- **Challenge:** The Broken Time Capsule
- **Category:** Rev
- **Flag:** `wctf{the_clock_keeps_its_secrets_dce922ea}`

---

## My initial read / first impressions

The challenge description says:

```text
We recovered a command-line restoration tool and a damaged time-capsule backup. The tool claims the backup is unreadable, but it may be waiting for the right sequence.

Usage: ./time_capsule backup.tc (each slot is a decimal byte)

Recover the message and submit it as the flag.
```

We get `dis.tar.gz`. Extracting it gives a binary and the backup:

```bash
tar -xzf dis.tar.gz
file time_capsule
```

```text
time_capsule: ELF 64-bit LSB executable, x86-64, statically linked, stripped
```

The description's usage line is a little misleading. Running the binary with only the backup gives:

```text
Usage: ./time_capsule <slot-1> <slot-2> <slot-3> <slot-4> <backup>
```

So we need four bytes, each from 0 to 255. Trying four zeroes doesn't work:

```bash
./time_capsule 0 0 0 0 backup.tc
```

```text
Backup index is damaged; try a different copy.
```

That's 256^4 possible inputs, so I started looking at how the binary checks them instead of brute forcing the whole thing.

## Looking at the backup format

The backup starts with `TCAP`, followed by a version byte and a count of 165 instructions. After the 10-byte header, each instruction is 7 bytes:

```python
opcode, a, b, imm = struct.unpack_from("<BBBI", data, offset)
```

That's one byte each for the opcode and two operands, then a little-endian 32-bit immediate.

The restoration tool runs these instructions in a small VM. The first instruction initializes register 0 to `0x6a09e667`. Later, register 4 gets initialized to `0xbb67ae85`.

The interesting part is that the program then repeats basically the same 15-instruction block four times for each register. Each block uses one of our four input bytes.

The operations include addition, XOR, bit rotations, multiplication, and a right-shift/XOR step. There is also a branch depending on whether the input-derived value is odd or even.

After those blocks, the backup has two checks:

```text
register 0 == 0x2ec29234
register 4 == 0x04de2a9c
```

Both have to pass. That's much more useful than the generic damaged-backup error.

## Reversing the checks

Each of the 15-instruction blocks can be written as a function that takes the current 32-bit state, one slot byte, and the constants from the backup.

The important part looks like this:

```python
k = (slot + add) & 0xffffffff
x = (x + k) & 0xffffffff
x ^= xor1
x = rol(x, rotation)
x = (x * multiplier) & 0xffffffff
x ^= x >> shift

if k & 1:
    x ^= xor2
else:
    x = (x + add2) & 0xffffffff
```

All of these steps can be undone. The multiplication constants are odd, so they have inverses modulo `2**32`. Rotations reverse with a rotate-right, and the `x ^= x >> shift` part can be inverted by applying the reverse relation a few times.

That gives us a way to work backward from the two target values.

Rather than test all four bytes together, I split them into two pairs:

- Try every `(slot0, slot1)` combination forward from both initial states and save the halfway values.
- Try every `(slot2, slot3)` combination backward from both target states.
- Match the halfway value for register 0, then check register 4 to eliminate the wrong matches.

Each half only has `256 * 256 = 65536` combinations. The register 0 check gave three possible sets of bytes, but only one also matched register 4:

```text
53 167 18 233
```

## Solution script

I parsed the instruction blocks directly from `backup.tc`, so the constants don't have to be copied out by hand.

```python
#!/usr/bin/env python3
import struct
import subprocess
from pathlib import Path

data = Path("backup.tc").read_bytes()
assert data[:4] == b"TCAP"

count = data[5]
instructions = [
    struct.unpack_from("<BBBI", data, 10 + i * 7)
    for i in range(count)
]
assert count == 165

MASK = 0xffffffff


def rol(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & MASK if n else x


def ror(x, n):
    return rol(x, 32 - (n & 31))


def undo_shift_xor(value, shift):
    x = value
    for _ in range(6):
        x = value ^ (x >> shift)
    return x


def get_round(start):
    block = instructions[start:start + 15]
    assert [row[0] for row in block] == [
        0x11, 0x26, 0x20, 0x27, 0x24,
        0x28, 0x12, 0x25, 0x21, 0x12,
        0x29, 0x30, 0x27, 0x32, 0x26,
    ]
    return {
        "add": block[1][3],
        "xor1": block[3][3],
        "rot": block[4][3],
        "mul": block[5][3],
        "shift": block[7][3],
        "xor2": block[12][3],
        "add2": block[14][3],
    }


a = [get_round(i) for i in (1, 16, 31, 46)]
b = [get_round(i) for i in (62, 77, 92, 107)]


def forward(x, slot, r):
    k = (slot + r["add"]) & MASK
    x = (x + k) & MASK
    x ^= r["xor1"]
    x = rol(x, r["rot"])
    x = (x * r["mul"]) & MASK
    x ^= x >> r["shift"]
    if k & 1:
        x ^= r["xor2"]
    else:
        x = (x + r["add2"]) & MASK
    return x


def backward(x, slot, r):
    k = (slot + r["add"]) & MASK
    if k & 1:
        x ^= r["xor2"]
    else:
        x = (x - r["add2"]) & MASK
    x = undo_shift_xor(x, r["shift"])
    x = (x * pow(r["mul"], -1, 1 << 32)) & MASK
    x = ror(x, r["rot"])
    x ^= r["xor1"]
    return (x - k) & MASK


left = {}
for s0 in range(256):
    x0 = forward(0x6a09e667, s0, a[0])
    y0 = forward(0xbb67ae85, s0, b[0])
    for s1 in range(256):
        x1 = forward(x0, s1, a[1])
        y1 = forward(y0, s1, b[1])
        left.setdefault(x1, []).append((s0, s1, y1))

matches = []
for s2 in range(256):
    for s3 in range(256):
        x = backward(0x2ec29234, s3, a[3])
        x = backward(x, s2, a[2])
        if x not in left:
            continue

        y = backward(0x04de2a9c, s3, b[3])
        y = backward(y, s2, b[2])
        for s0, s1, y1 in left[x]:
            if y1 == y:
                matches.append((s0, s1, s2, s3))

assert len(matches) == 1
slots = matches[0]
print("Slots:", *slots)
subprocess.run(
    ["./time_capsule", *(str(s) for s in slots), "backup.tc"],
    check=True,
)
```

Running it in the extracted directory:

```bash
chmod +x time_capsule
python3 solve.py
```

```text
Slots: 53 167 18 233
wctf{the_clock_keeps_its_secrets_dce922ea}
```

## Why this works

The backup isn't missing data. The restoration tool is checking four input bytes by running them through two separate chains of 32-bit operations. Since each round is reversible, we can meet in the middle instead of searching all four bytes at once.

Once both register checks pass, the binary restores the message normally.

## Final flag

```text
wctf{the_clock_keeps_its_secrets_dce922ea}
```
