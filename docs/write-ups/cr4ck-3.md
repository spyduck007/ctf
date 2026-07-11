---
title: Cr4ck 3
date: 2026-07-06
tags:
- rev
- LYKNCTF
---

- **Challenge:** Cr4ck 3
- **Category:** Rev
- **Flag:** `LYKNCTF{Dyn4m1c_0nly_LYKN_2026!!}`

---

## My initial read / first impressions

The challenge name was **Cr4ck 3**, and the description was just:

```text
Cr4ck Cr4ck Cr4ck
```

We are given a Windows executable:

```text
Serial.exe
```

So from the name alone, this looked like a classic serial / flag checker. I expected either a hardcoded serial hiding somewhere or a checker function that transformed the input and compared it against some constants.

The flag was not just sitting directly in `strings`, but the format was pretty clear after looking at the validation logic. The program expects:

```text
LYKNCTF{........................}
```

where the inside has exactly 24 characters.

So the total flag length is:

```text
8 byte prefix + 24 byte body + 1 byte suffix = 33 bytes
```

## Finding the actual check

The first layer of the check is just normal format validation:

```text
starts with LYKNCTF{
ends with }
inner length is 24
```

After that, the interesting part starts. Each of the 24 inner characters is processed one at a time.

At first I thought this might just be a normal character transform, but it was slightly more annoying than that. The binary uses a small obfuscated VM-ish routine to transform each character, then compares the low 16 bits of the result against a target table.

The important part is that the state is dynamic. The checker does not treat each character completely independently. After a character is correct, the result becomes the new base value, and the seed also gets updated.

So the shape is basically:

```text
check char 0 using initial state
    -> update base and seed
check char 1 using new state
    -> update base and seed
check char 2 using new state
    -> ...
```

This means we cannot just solve every character with one static equation. We have to solve them in order.

## The dynamic state

The binary hashes its `.text` section and uses that to derive the initial state. For the provided executable, the useful values ended up being:

```python
base = 0x613cdcaa
seed = base ^ 0xa5a5a5a5
```

The constants used by the transform were:

```python
C = 0x9c5ab3d7
A = 0x3f1e5c2b
```

The target table had 24 values, one for each inner character:

```python
targets = [
    0x526e, 0xbb33, 0x417f, 0x11d4, 0xcef9, 0x9caf,
    0xbdf1, 0x3623, 0x337c, 0xe83c, 0xc20b, 0x915c,
    0x2664, 0xc495, 0x70c4, 0xbfb0, 0x8bd2, 0x716a,
    0x2081, 0xb422, 0x8ae5, 0x2a77, 0xb1f9, 0xdd9e
]
```

Once I had those pieces, the challenge became much less scary. Since each flag character is printable ASCII, I only needed to try characters from `0x20` to `0x7e` for each position.

For each candidate character:

1. Run the same transform as the binary.
2. Check whether `result & 0xffff` matches the current target.
3. If it matches, keep that character and update the state.
4. Move on to the next target.

## Rewriting the checker

The transform looked like this after cleaning it up:

```python
x = base
t = (ch * 0x53 + seed) & 0xffffffff
x ^= t
x = rol(x, 7)
x ^= x >> 13
x = (x + seed) & 0xffffffff
x = (x * C) & 0xffffffff
x = rol(x, 11)
x ^= x >> 17
x = (x + A) & 0xffffffff
```

Then the checker compares:

```python
x & 0xffff
```

against the target for that position.

The state update after a correct character is:

```python
base = x
seed = rol((seed * C + A) & 0xffffffff, 13)
```

That explains the flag text too. The challenge is literally about the check being dynamic only.

## Solution Script

Here is the final solve script I used.

```python
def rol(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

C = 0x9c5ab3d7
A = 0x3f1e5c2b

base = 0x613cdcaa
seed = base ^ 0xa5a5a5a5

targets = [
    0x526e, 0xbb33, 0x417f, 0x11d4, 0xcef9, 0x9caf,
    0xbdf1, 0x3623, 0x337c, 0xe83c, 0xc20b, 0x915c,
    0x2664, 0xc495, 0x70c4, 0xbfb0, 0x8bd2, 0x716a,
    0x2081, 0xb422, 0x8ae5, 0x2a77, 0xb1f9, 0xdd9e
]

body = ""

for target in targets:
    found = False

    for ch in range(0x20, 0x7f):
        x = base
        t = (ch * 0x53 + seed) & 0xffffffff

        x ^= t
        x = rol(x, 7)
        x ^= x >> 13
        x = (x + seed) & 0xffffffff
        x = (x * C) & 0xffffffff
        x = rol(x, 11)
        x ^= x >> 17
        x = (x + A) & 0xffffffff

        if (x & 0xffff) == target:
            body += chr(ch)
            base = x
            seed = rol((seed * C + A) & 0xffffffff, 13)
            found = True
            break

    if not found:
        raise RuntimeError("could not solve next character")

print("LYKNCTF{" + body + "}")
```

Running it prints:

```text
LYKNCTF{Dyn4m1c_0nly_LYKN_2026!!}
```

## Why this works

The checker looks annoying because of the obfuscation and the VM-style transform, but the actual search space is tiny once the logic is copied out.

Each character only has around 95 printable possibilities. Since the state update only happens after finding the correct character, we can solve the flag from left to right.

So instead of brute forcing the whole 24-character body, the solve is basically:

```text
24 positions * ~95 printable guesses
```

which is nothing.

The main thing was noticing that the state was dynamic. If I tried to solve every position using only the original `base` and `seed`, the results would be wrong after the first character. Once I updated the state exactly like the binary did, the whole flag fell out cleanly.

## Flag

```text
LYKNCTF{Dyn4m1c_0nly_LYKN_2026!!}
```
