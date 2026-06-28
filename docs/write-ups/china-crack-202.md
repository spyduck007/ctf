---
title: China Crack? - 202
date: 2026-06-26
tags:
- crypto
- V1T-CTF-2026
---

- **Challenge:** China Crack? - 202
- **Category:** Crypto
- **Flag:** `V1T{7fK9xL2mQp8ZrT5uWc3Yd6Hs0AaBbCcDdEeFf}`

---

## My initial read / first impressions

We are given a Python script that encrypts the flag and prints a few different "leaks" about the encryption state. At first glance, it looks like a pretty normal AES-style crypto challenge because the script imports AES and has values named `KEY`, `IV`, and `cipher_flag`.

But looking closer, the first weird thing is that the `KEY` and `IV` values are fake.

They look like this:

```python
KEY = bytes.fromhex("THIS_IS_NOT_THE_REAL_KEY")
IV = bytes.fromhex("THIS_IS_NOT_THE_REAL_IV")
```

That obviously cannot work, since `bytes.fromhex()` expects actual hex characters. So if this script was run normally, it would just crash before doing anything useful.

That means the actual challenge is not to use the key or decrypt AES normally. The important values are the printed ciphertext and the leak arrays.

The challenge gives us:

- `cipher_flag`
- `leak1`
- `leak2`
- `leak3`
- `crc`

So the real goal is to recover the keystream used to encrypt the flag, then XOR it with the ciphertext.

## Understanding the encryption

The flag is encrypted by XORing it with a keystream. The keystream is split into 32-bit words.

Each 32-bit word gives 4 bytes of keystream.

So if we can recover the keystream words, we can decrypt the ciphertext directly.

The script leaks information about each 32-bit word in three different ways.

The most important leak is `leak2`:

```python
leak2.append(((word * 0x45d9f3b) ^ (word >> 16)) & 0xFFFF)
```

This only gives us 16 bits, but the useful part is that it relates the lower 16 bits and upper 16 bits of the word.

If we split the word like this:

```python
word = (high16 << 16) | low16
```

Then `word >> 16` is just `high16`.

Also, because the leak only keeps the bottom 16 bits, the multiplication part only depends on `low16`.

So the equation becomes:

```python
leak2 = ((low16 * 0x45d9f3b) ^ high16) & 0xFFFF
```

That means if we guess `low16`, we can directly solve for `high16`.

```python
high16 = leak2 ^ ((low16 * 0x45d9f3b) & 0xFFFF)
```

This is the main shortcut. Instead of brute forcing all `2^32` possible words, we only need to brute force `2^16` possible low halves for each word.

## Using the other leaks

The second useful leak is `leak3`:

```python
leak3.append(bin(word).count("1"))
```

This gives the popcount of each word, meaning the number of `1` bits in the full 32-bit word.

So after generating candidate words using `leak2`, we can filter them by checking if their popcount matches `leak3`.

The third leak is `leak1`:

```python
leak1.append((((words[i] ^ words[i + 1]) * 0x9e3779b1) >> 24) & 0xFF)
```

This leak connects adjacent words.

It does not tell us a single word by itself, but it lets us check whether two neighboring word candidates are compatible.

So the strategy becomes:

1. Use `leak2` to generate possible candidates for each word.
2. Filter each candidate using `leak3`.
3. Decrypt candidate bytes and keep only printable flag-looking characters.
4. Chain the words together using `leak1`.
5. Use the known flag format and CRC to confirm the result.

## The important observation

The flag starts with:

```text
V1T{
```

and ends with:

```text
}
```

This gives us a lot of structure.

Since each keystream word decrypts 4 bytes, we can reject tons of candidates by checking whether:

```python
cipher_word ^ keystream_word
```

produces printable characters.

This is especially strong here because the flag is made of normal printable characters.

The CRC is also useful:

```python
crc32(flag[:16]) = 0x32c29a97
```

So once we get a possible flag, we can verify that the first 16 bytes match the provided CRC. That makes it very unlikely that we accidentally found a fake solution.

## Solution Script

Here is the final solve script I used.

```python
import ast
import re
import zlib

with open("challenge.py", "r") as f:
    s = f.read()

cipher_flag = bytes.fromhex(re.search(r'cipher_flag\s*=\s*"([0-9a-f]+)"', s).group(1))
leak1 = ast.literal_eval(re.search(r"leak1\s*=\s*(\[.*?\])", s, re.S).group(1))
leak2 = ast.literal_eval(re.search(r"leak2\s*=\s*(\[.*?\])", s, re.S).group(1))
leak3 = ast.literal_eval(re.search(r"leak3\s*=\s*(\[.*?\])", s, re.S).group(1))
crc = int(re.search(r"crc\s*=\s*(0x[0-9a-fA-F]+|\d+)", s).group(1), 0)

n = (len(cipher_flag) + 3) // 4
chunks = [cipher_flag[i * 4:(i + 1) * 4] for i in range(n)]

def popcount(x):
    return x.bit_count()

def printable(bs):
    return all(32 <= b <= 126 for b in bs)

def valid_flag_bytes(pos, bs):
    for j, b in enumerate(bs):
        idx = pos * 4 + j
        if idx >= len(cipher_flag):
            continue
        c = chr(b)
        if idx == 0 and c != "V":
            return False
        if idx == 1 and c != "1":
            return False
        if idx == 2 and c != "T":
            return False
        if idx == 3 and c != "{":
            return False
        if idx == len(cipher_flag) - 1 and c != "}":
            return False
        if idx > 3 and idx < len(cipher_flag) - 1:
            if c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}":
                return False
    return printable(bs)

candidates = []

for i in range(n):
    cur = []
    for low in range(1 << 16):
        high = leak2[i] ^ ((low * 0x45d9f3b) & 0xffff)
        word = ((high << 16) | low) & 0xffffffff

        if popcount(word) != leak3[i]:
            continue

        ks = word.to_bytes(4, "little")
        pt = bytes(a ^ b for a, b in zip(chunks[i], ks))

        if valid_flag_bytes(i, pt):
            cur.append((word, pt))

    candidates.append(cur)
    print(i, len(cur))

path = []

def dfs(i):
    if i == n:
        flag = b"".join(x[1] for x in path)[:len(cipher_flag)]
        if flag.startswith(b"V1T{") and flag.endswith(b"}"):
            if zlib.crc32(flag[:16]) & 0xffffffff == crc:
                print(flag.decode())
                return True
        return False

    for word, pt in candidates[i]:
        if i > 0:
            prev = path[-1][0]
            check = (((prev ^ word) * 0x9e3779b1) >> 24) & 0xff
            if check != leak1[i - 1]:
                continue

        path.append((word, pt))
        if dfs(i + 1):
            return True
        path.pop()

    return False

dfs(0)
```

Running it gives:

```text
V1T{7fK9xL2mQp8ZrT5uWc3Yd6Hs0AaBbCcDdEeFf}
```

## Why this works

The fake AES key and IV are basically bait. The actual encryption is broken because the challenge leaks too much information about the keystream.

`leak2` is the biggest issue because it lets us reduce each 32-bit word down to only `2^16` possibilities. Then `leak3` cuts that down even more using the popcount. After that, printable flag checks and the adjacent-word `leak1` relation make the search tiny.

Finally, the CRC confirms the recovered flag is the intended one.

So the final flag is:

```text
V1T{7fK9xL2mQp8ZrT5uWc3Yd6Hs0AaBbCcDdEeFf}
```