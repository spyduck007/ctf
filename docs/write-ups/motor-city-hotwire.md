---
title: Motor City Hotwire
date: 2026-11-20
tags:
- rev
- WolvCTF-2026
---

- **Challenge:** Motor City Hotwire
- **Category:** Rev
- **Flag:** `wctf{5M0OTH_0P3R4TORRRRR_6ef709d1ac21}`

---

## My initial read / first impressions

The challenge description says:

```text
We pulled this firmware off a control module during a teardown in the Motor City. Help us find its secret.

The download is a stripped ARM Thumb ELF for offline analysis. There is no live CAN interface or network service; its request and response behavior can be studied by disassembly or emulation.
```

We get `dis (3).tar.gz`, which has one file inside:

```bash
tar -tzf "dis (3).tar.gz"
tar -xzf "dis (3).tar.gz"
file firmware.bin
```

```text
firmware.bin
firmware.bin: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, stripped
```

The entry point is `0x8001`, so this is Thumb code. There isn't a normal program to run or a service to connect to, so I went through the disassembly instead.

```bash
llvm-objdump -d --triple=thumbv7m-none-eabi firmware.bin
```

## Finding the security access handler

Around `0x84a0`, the firmware checks the first request byte against `0x27`. That's the UDS SecurityAccess service. It handles two subfunctions:

- `27 01` asks for the seed.
- `27 02` sends back an 8-byte key.

The seed is hardcoded in the firmware:

```text
1a2b3c4d5e6f7788
```

The key request has to be 10 bytes total: `27 02` followed by the 8 key bytes. I originally expected to find a comparison against the correct key somewhere in that handler.

There isn't one. The handler runs the key through a custom mixer, uses the result to decrypt some embedded bytes, and sends the output back. A wrong key still goes through the same code, but the decrypted text is garbage.

## Reversing the key mixer

The setup routine at `0x8234` builds a 256-byte substitution table and the parameters for 16 rounds. The values come from a fixed xorshift64 state:

```text
initial state = 0xa5a5f00dc0de1234
multiplier    = 0x4f6cdd1d
rounds        = 16
```

It first shuffles a table containing `0` through `255`. Then it generates six values for each round: two multipliers, two other constants, a rotation amount, and a branch selector.

The round function at `0x8010` multiplies a 32-bit word, replaces its four bytes using that table, rotates the result, adds a constant, and XORs another constant. The surrounding code mixes two 32-bit halves of the key with this function.

Trying random keys would be pointless here. But the mixer is reversible. Both round multipliers are forced to be odd with `| 1`, so they have modular inverses modulo `2^32`. The other operations are XORs and swaps, which we can undo in reverse order.

The firmware XORs the mixed key with the fixed seed before hashing it. I tried making that XOR result zero:

```text
mixer(key) = 1a2b3c4d5e6f7788
```

Reversing all 16 rounds from that value gives:

```text
1b869bc58e96b90b
```

So the full `27 02` request is:

```text
27 02 1b 86 9b c5 8e 96 b9 0b
```

## Decrypting the secret

The rest of the handler uses SHA-256 to generate bytes that get XORed with the encrypted secret. The encrypted data is 38 bytes long and starts at virtual address `0x88f8`.

The ELF's loadable data starts at file offset `0x1000` for virtual address `0x8000`, so the ciphertext is at file offset `0x18f8`:

```python
ciphertext = firmware[0x18f8:0x191e]
```

Once the mixer output matches the seed, the first 8 bytes of the SHA input are zero. The next 8 bytes are the key packed as two little-endian 32-bit words. The firmware appends a little-endian counter and hashes that with SHA-256, giving 32 bytes of keystream per counter.

We only need two blocks for the 38-byte ciphertext:

```python
header = b"\0" * 8 + struct.pack("<II", key_lo, key_hi)
stream = b"".join(
    hashlib.sha256(header + struct.pack("<I", counter)).digest()
    for counter in range(2)
)
flag = bytes(c ^ k for c, k in zip(ciphertext, stream))
```

That decrypts to a valid `wctf{...}` flag.

## Solution script

I put the table generation, inverse rounds, and decryption into one Python script. It reads either the original archive or the extracted `firmware.bin`, and only uses the standard library.

```python
#!/usr/bin/env python3
import hashlib
import struct
import sys
import tarfile

MASK = 0xffffffff
MASK64 = 0xffffffffffffffff
MULT = 0x4f6cdd1d
SEED_HI = 0x1a2b3c4d
SEED_LO = 0x5e6f7788


def xorshift64(x):
    x ^= x >> 12
    x ^= (x << 25) & MASK64
    x ^= x >> 27
    return x & MASK64


def random_word(x):
    return ((x & MASK) * MULT) & MASK


def build_rounds():
    state = (0xa5a5f00d << 32) | 0xc0de1234
    sbox = list(range(256))

    for i in range(255, 0, -1):
        state = xorshift64(state)
        j = random_word(state) % (i + 1)
        sbox[i], sbox[j] = sbox[j], sbox[i]

    rounds = []
    for _ in range(16):
        words = []
        for _ in range(6):
            state = xorshift64(state)
            words.append(random_word(state))
        a, b, c, d, rot, branch = words
        rounds.append((a | 1, b | 1, c, d, rot % 31 + 1, branch & 1))

    return sbox, rounds


def rol32(x, bits):
    return ((x << bits) | (x >> (32 - bits))) & MASK


def recover_key(sbox, rounds):
    # Start from the seed and undo each round.
    lo, hi = SEED_LO, SEED_HI

    for a, b, c, d, rot, branch in reversed(rounds):
        def nonlinear(x):
            x = (x * b) & MASK
            sub = sum(
                sbox[(x >> (8 * i)) & 0xff] << (8 * i)
                for i in range(4)
            )
            return c ^ ((rol32(sub, rot) + d) & MASK)

        inverse = pow(a, -1, 1 << 32)
        if branch:
            hi, lo = (lo * inverse) & MASK, hi ^ nonlinear(lo)
        else:
            hi, lo = ((lo ^ nonlinear(hi)) * inverse) & MASK, hi

    return lo, hi


def load_firmware(filename):
    if filename.endswith((".tar.gz", ".tgz")):
        with tarfile.open(filename, "r:gz") as tar:
            return tar.extractfile("firmware.bin").read()
    with open(filename, "rb") as f:
        return f.read()


firmware = load_firmware(sys.argv[1])
sbox, rounds = build_rounds()
key_lo, key_hi = recover_key(sbox, rounds)
key = struct.pack(">II", key_hi, key_lo)

header = b"\0" * 8 + struct.pack("<II", key_lo, key_hi)
ciphertext = firmware[0x18f8:0x191e]

stream = b"".join(
    hashlib.sha256(header + struct.pack("<I", counter)).digest()
    for counter in range(2)
)
flag = bytes(c ^ k for c, k in zip(ciphertext, stream))

print("Seed:", f"{SEED_HI:08x}{SEED_LO:08x}")
print("Key:", key.hex())
print("Request:", (b"\x27\x02" + key).hex())
print("Flag:", flag.decode())
```

Running it on the archive:

```bash
python3 solve.py "dis (3).tar.gz"
```

```text
Seed: 1a2b3c4d5e6f7788
Key: 1b869bc58e96b90b
Request: 27021b869bc58e96b90b
Flag: wctf{5M0OTH_0P3R4TORRRRR_6ef709d1ac21}
```

## Why this works

The security key isn't checked against a stored value. It controls the decryption instead. The 16-round mixer looks annoying, but every round can be inverted because the multipliers are odd and all the other operations are reversible.

Setting the mixed key equal to the hardcoded seed cancels out the first 8 bytes of the SHA input. That gives us a key we can recover by running the mixer backward. With that key, the SHA-256 keystream decrypts the firmware's 38-byte blob into the flag.

## Final flag

```text
wctf{5M0OTH_0P3R4TORRRRR_6ef709d1ac21}
```
