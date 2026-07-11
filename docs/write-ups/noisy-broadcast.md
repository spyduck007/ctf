---
title: Noisy Broadcast
date: 2026-07-06
tags:
- crypto
- LYKNCTF
---

- **Challenge:** Noisy Broadcast
- **Category:** Crypto
- **Flag:** `LYKNCTF{n01sy_CRT_w1th_K4nn4n_3mb3dd1ng}`

---

## My initial read / first impressions

The challenge description says:

```text
The same secret message was broadcast to three different recipients. Unfortunately, the communication channel was noisy — each recipient received a random ciphertext Can you recover the original plaintext.
```

The provided `output.txt` gives three RSA-looking public keys/ciphertexts:

```python
e = 3
n1 = ...
c1 = ...
n2 = ...
c2 = ...
n3 = ...
c3 = ...
```

As soon as I saw `e = 3` and the same message being sent to three different recipients, my first thought was the classic RSA broadcast attack / Hastad attack.

Normally, if the same plaintext `m` is encrypted with small exponent `e = 3` under three different coprime moduli, we have:

```text
c1 = m^3 mod n1
c2 = m^3 mod n2
c3 = m^3 mod n3
```

Then CRT combines the three ciphertexts into the actual integer `m^3`, and taking an integer cube root gives the plaintext.

But the challenge title and description both mention noise, so the ciphertexts are not perfectly clean RSA ciphertexts. That means the normal CRT result will not be a perfect cube anymore.

## The noisy part

The important thing is that the ciphertexts are extremely close to each other. They all share the same giant prefix and only differ near the end.

That suggests the challenge is doing something like:

```text
c_i = m^3 + small_noise_i
```

instead of clean RSA encryption.

So even though the usual CRT cube-root attack is technically broken by the noise, the plaintext is still recoverable because the noise is tiny compared to the gap between consecutive cubes near `m`.

Near a large integer `m`, the gap between cubes is roughly:

```text
(m + 1)^3 - m^3 = 3m^2 + 3m + 1
```

Our plaintext is a flag string, so `m` is already hundreds of bits long. That makes the cube gap enormous. If the noise is only a few dozen bits, it will not move the ciphertext closer to a different cube.

So the plan became:

```text
for each noisy ciphertext c_i:
    take the integer cube root
    try the nearby roots
    convert the candidate integer back to bytes
    check for LYKNCTF{...}
```

This is basically the lazy version of noisy broadcast recovery. If the noise had been much larger, this would turn into a real lattice / Kannan embedding problem. The flag even hints at that. But for this instance, the noise is small enough that nearest cube root just works.

## Recovering the plaintext

I used an integer cube root instead of floating point, because these numbers are huge and floats will absolutely betray you here.

The script checks `root - 2` through `root + 2` for each ciphertext, since the rounded cube root could be off by one depending on whether the ciphertext is slightly above or below `m^3`.

## Solution Script

Here is the final solve script I used. It reads the provided `output.txt`, tries cube roots of each noisy ciphertext, and prints the flag once the bytes decode correctly.

```python
#!/usr/bin/env python3
import re
from pathlib import Path


def integer_cube_root(n):
    lo = 0
    hi = 1

    while hi ** 3 <= n:
        hi *= 2

    while lo + 1 < hi:
        mid = (lo + hi) // 2

        if mid ** 3 <= n:
            lo = mid
        else:
            hi = mid

    return lo


def long_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


def parse_output(path):
    text = Path(path).read_text()
    vals = {}

    for name, value in re.findall(r"(e|n1|c1|n2|c2|n3|c3) = ([0-9]+)", text):
        vals[name] = int(value)

    return vals


def main():
    vals = parse_output("output.txt")
    ciphertexts = [vals["c1"], vals["c2"], vals["c3"]]

    for idx, c in enumerate(ciphertexts, 1):
        root = integer_cube_root(c)

        for candidate in range(root - 2, root + 3):
            if candidate < 0:
                continue

            plaintext = long_to_bytes(candidate)

            if b"LYKNCTF{" in plaintext:
                print(f"[+] Found using c{idx}")
                print(plaintext.decode())
                return

    print("[-] No flag found")


if __name__ == "__main__":
    main()
```

Running it gives:

```text
[+] Found using c1
LYKNCTF{n01sy_CRT_w1th_K4nn4n_3mb3dd1ng}
```

## Why this works

The challenge is trying to look like a noisy version of Hastad's broadcast attack.

The normal broadcast attack is:

```text
same plaintext + e = 3 + three moduli
    -> CRT
    -> exact cube root
    -> flag
```

Here, the ciphertexts are noisy, so CRT no longer gives an exact cube. But the plaintext is small enough that `m^3` does not wrap around the moduli, and the noise is tiny enough that `c_i` is still closest to the correct cube.

For the recovered flag, the differences from the true cube are only:

```text
c1 - m^3 =  2^52
c2 - m^3 = -2^42
c3 - m^3 = -2^68
```

That is basically nothing compared to the size of `m^3`, so taking the nearby integer cube root immediately recovers `m`.

So the actual bug is still the classic RSA mistake: using a tiny public exponent with no padding on the same plaintext. The added noise makes the clean textbook attack fail, but it is not large enough to hide the cube root.
