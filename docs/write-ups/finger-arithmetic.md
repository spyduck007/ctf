---
title: Finger Arithmetic
date: 2026-06-26
tags:
- rev
- TraceBash-CTF-2026
---

- **Challenge:** Finger Arithmetic
- **Category:** Rev
- **Flag:** `TBCTF{ju75u5_n_d34d_3nd5_4w417!}`

---

## My initial read / first impressions

We are given a Linux binary called `chall`. Running it gives a very simple prompt:

```text
Enter the flag:
```

The challenge description says it expects a 32-character key, so my first thought was that this was probably just a normal flag checker with some annoying validation routine.

I started with the usual basic checks:

```bash
file chall
strings chall
nm -C chall
```

The binary was a 64-bit PIE executable, but luckily it was not stripped. The interesting symbols were still there, especially:

```text
main
validate_checksum_v2
compare_hand_png_i32
```

The name `compare_hand_png_i32` immediately made the challenge feel weird. There were also a ton of `lodepng` symbols, which means the binary was doing PNG encoding/decoding internally. So instead of just comparing integers directly, it was doing some goofy PNG-based validation.

## Understanding the Main Checks

Looking at `main`, the program reads the input, removes the newline, and then does a few checks before the real validation.

The important checks were:

- The input length must be `32`.
- The first 4 bytes must match `TBCT`.
- One specific byte must be `{`.
- Then the full input is passed into `validate_checksum_v2`.

The first 4-byte check is little endian, so the value being checked is:

```text
0x54434254
```

In memory, that is:

```text
TBCT
```

That already made it pretty clear the final flag was going to be in the normal `TBCTF{...}` format.

## The Weird PNG Obfuscation

The annoying part was that the program was not doing something clean like:

```c
if (x == 0x12345678)
```

Instead, it was doing something more like:

```c
compare_hand_png_i32(x, embedded_png_blob, blob_size)
```

Each expected integer was hidden as an embedded PNG. The binary would take the candidate integer, render it as a hand/finger image, and compare that rendered PNG against the embedded PNG.

So the constants were not sitting in the binary as normal hex numbers. They were hidden as images.

Very funny. Very cursed.

The important thing is that this was still just obfuscation. The actual validation logic was normal arithmetic. Once I decoded the PNG targets back into integers, the rest of the challenge became very straightforward.

## Reversing the Arithmetic

Inside `validate_checksum_v2`, the input is treated as 8 little-endian 32-bit integers.

So a 32-character input becomes:

```text
w0, w1, w2, w3, w4, w5, w6, w7
```

The validation chain looks like this:

```c
t0 = w0 + 0x11223344;
t1 = w1 ^ t0;
t2 = w2 - t1;
t3 = w3 ^ t2;
t4 = w4 + t3;
t5 = w5 ^ t4;
t6 = w6 - t5;
t7 = w7 ^ t6;
```

After each step, the program compares the result against one of those hand PNG constants.

So the actual math was not hard. The challenge was mostly hiding the constants.

After extracting/matching the embedded hand PNGs, the target values were:

```python
targets = [
    0x65657598,
    0x100f0ede,
    0x25662659,
    0x41394806,
    0xa09d7c39,
    0x95f9120a,
    0x9e7e2255,
    0xe35f1564
]
```

Now we can reverse the equations.

If:

```text
t0 = w0 + 0x11223344
```

then:

```text
w0 = t0 - 0x11223344
```

If:

```text
t1 = w1 ^ t0
```

then:

```text
w1 = t1 ^ t0
```

And so on.

For subtraction steps, we add the previous value back. For XOR steps, we XOR again, since XOR reverses itself.

## Solution Script

Here is the final solve script:

```python
import struct

targets = [
    0x65657598,
    0x100f0ede,
    0x25662659,
    0x41394806,
    0xa09d7c39,
    0x95f9120a,
    0x9e7e2255,
    0xe35f1564
]

words = [0] * 8

words[0] = (targets[0] - 0x11223344) & 0xffffffff
words[1] = targets[1] ^ targets[0]
words[2] = (targets[2] + targets[1]) & 0xffffffff
words[3] = targets[3] ^ targets[2]
words[4] = (targets[4] - targets[3]) & 0xffffffff
words[5] = targets[5] ^ targets[4]
words[6] = (targets[6] + targets[5]) & 0xffffffff
words[7] = targets[7] ^ targets[6]

flag = struct.pack("<8I", *words).decode()

print(flag)
```

Running it gives:

```text
TBCTF{ju75u5_n_d34d_3nd5_4w417!}
```

## Verifying the Flag

Finally, I ran the binary with the recovered input:

```text
Enter the flag: TBCTF{ju75u5_n_d34d_3nd5_4w417!}
Correct! The flag is the input you entered.
```

And that confirms the solve.

## Final Flag

```text
TBCTF{ju75u5_n_d34d_3nd5_4w417!}
```
