---
title: Control Freak 1
date: 2026-07-06
tags:
- rev
- LYKNCTF
---

- **Challenge:** Control Freak 1
- **Category:** Rev
- **Flag:** `LYKNCTF{H0W_D1D_Y0U_C0NTR0L_TH4T}`

---

## My initial read / first impressions

The challenge description says:

```text
A tiny checker that really likes being in control. Can you figure out who controls the bytes in the end?
```

We are given a Windows binary:

```text
chall-2.exe
```

Running it is exactly what you would expect from a tiny rev checker. It asks for a flag, does some byte checks, and prints whether the input is accepted or not.

The important hint is in the wording: "who controls the bytes in the end?" That made me look for a final transformed buffer instead of expecting a direct string compare. Basically, the input bytes get thrown through a small custom mixer, and the program only compares the final mangled result against a target.

So the plan was:

```text
find the target bytes
    -> recover the byte transformation
    -> invert the transformation
    -> get the original input
```

## Finding the checker

The binary is small, so the real checker was not too bad to find. The input length check is the first useful detail: the program wants exactly `33` bytes.

That already lines up with a normal LYKNCTF flag length:

```text
LYKNCTF{...}
```

After the length check, the program does not compare the input directly. Instead, it transforms the 33-byte buffer for 3 rounds and then compares the result against a 33-byte target in `.rdata`.

The target bytes were:

```text
66 15 e4 34 0c 1b 3e d3 22 d1 ea 25 86 12 88 6f
ae 57 72 18 c9 db 10 36 3e 0b 48 07 44 f9 01 ff 07
```

At this point, the challenge becomes way easier if you stop trying random inputs and just reverse the transform.

## Understanding the transform

Each round does three main things.

First, every byte is individually changed using an XOR key, a rotate, and an addition:

```text
x = input[i]
x ^= key1[(i + 3 * round) % 8]
x = rol8(x, ((i + round) % 7) + 1)
x += key2[(round + 5 * i) % 8] + 0x1d * round + 13 * i
```

The constants are:

```text
key1 = "RdqQTv-9"
key2 = 17 8b 23 42 c1 5e 09 a7
```

Then the bytes are permuted with this fixed permutation:

```python
perm = [
    3, 10, 17, 24, 31, 5, 12, 19, 26, 0, 7,
    14, 21, 28, 2, 9, 16, 23, 30, 4, 11, 18,
    25, 32, 6, 13, 20, 27, 1, 8, 15, 22, 29,
]
```

Finally, there is a feedback XOR pass. This part makes the output byte depend on the previous state, which looks annoying at first, but it is still completely reversible.

The feedback logic is basically:

```text
state = 0x5a + 0x31 * round
for each byte:
    t = permuted[i] ^ (round + 7 * i)
    state ^= t
    output[i] = state
```

So the checker has a lot of tiny operations, but nothing one-way. XOR, rotate, addition mod 256, permutation, and feedback XOR are all invertible.

## Reversing it

Since the program compares the final transformed bytes against the target, I just started from the target and ran everything backwards.

The inverse order for each round is:

```text
undo feedback XOR
    -> undo permutation
    -> undo add
    -> undo rotate
    -> undo XOR
```

The only slightly non-obvious part is undoing the feedback pass. During the forward pass, each output byte becomes the new state. So when reversing, the previous state is either the round's initial state or the previous output byte.

That gives:

```text
permuted[i] = output[i] ^ previous_state ^ (round + 7 * i)
previous_state = output[i]
```

Then the rest is just normal inverse operations.

## Solve script

This is the script I used to reverse the final target bytes back into the accepted input:

```python
def rol8(x, c):
    c %= 8
    return ((x << c) & 0xff) | (x >> (8 - c)) if c else x


def ror8(x, c):
    c %= 8
    return (x >> c) | ((x << (8 - c)) & 0xff) if c else x


key1 = b"RdqQTv-9"
key2 = bytes.fromhex("178b2342c15e09a7")

target = bytes.fromhex(
    "6615e4340c1b3ed322d1ea258612886f"
    "ae577218c9db10363e0b480744f901ff07"
)

perm = [
    3, 10, 17, 24, 31, 5, 12, 19, 26, 0, 7,
    14, 21, 28, 2, 9, 16, 23, 30, 4, 11, 18,
    25, 32, 6, 13, 20, 27, 1, 8, 15, 22, 29,
]

buf = bytearray(target)

for r in range(2, -1, -1):
    # Undo feedback XOR.
    out = bytearray(33)
    prev = (0x5a + 0x31 * r) & 0xff

    for i in range(33):
        out[i] = (buf[i] ^ prev ^ ((r + 7 * i) & 0xff)) & 0xff
        prev = buf[i]

    # Undo permutation.
    temp = bytearray(33)
    for i, p in enumerate(perm):
        temp[i] = out[p]

    # Undo byte transform.
    for i in range(33):
        add = (key2[(r + 5 * i) & 7] + ((0x1d * r) & 0xff) + 13 * i) & 0xff
        x = (temp[i] - add) & 0xff
        x = ror8(x, ((i + r) % 7) + 1)
        temp[i] = x ^ key1[(i + 3 * r) & 7]

    buf = temp

print(bytes(buf).decode())
```

Running it prints:

```text
LYKNCTF{H0W_D1D_Y0U_C0NTR0L_TH4T}
```

## Verifying it

After recovering the input, the clean way to verify is just to run the checker normally and paste the flag.

The important part is that the recovered bytes are exactly 33 bytes long and their forward transform matches the embedded target:

```text
forward(flag) == target
```

That confirms we reversed the checker instead of just guessing something that looked flag-shaped.

## Why this works

The challenge tries to hide the flag by making the final bytes look unrelated to the input. But every step keeps the information intact:

```text
XOR      -> invert with the same XOR
ROL      -> invert with ROR
ADD      -> invert with subtraction mod 256
PERMUTE  -> invert with the inverse permutation
FEEDBACK -> invert using the previous output byte as state
```

So even though the program is very controlling about where each byte goes, the bytes are still recoverable. Once the final target and constants are known, the accepted input falls out directly.

## Flag

```text
LYKNCTF{H0W_D1D_Y0U_C0NTR0L_TH4T}
```
