---
title: Remedy
date: 2026-07-06
tags:
- forensics
- LYKNCTF
---

- **Challenge:** Remedy
- **Category:** Forensics
- **Flag:** `LYKNCTF{Would_Be_Nice_If_Someone_Grow_Up_One_Day}`

---

## My initial read / first impressions

The challenge description was extremely short:

```text
Just a random pic?
```

We are only given a PNG image. Visually, it just looks like a normal anime-style picture, so this immediately felt like a classic image forensics / stego challenge.

For these, I usually do the boring checks first before jumping into more painful things like bit planes or LSB extraction:

```bash
file challeng.png
exiftool challeng.png
strings -a challeng.png | head
binwalk challeng.png
```

A lot of image challenges try to bait you into staring at the pixels forever, but in this case the actual clue was in the metadata.

## Finding the suspicious metadata

Running `exiftool` showed a suspicious `Description` field:

```text
Description : 6d14166842b6ecb67622284a65bde8a87e03344564bde3ab7e1e324b648dc4a87e0a2f4976bdffbd7e0233435ea6cbb45c
```

That is way too structured to be random metadata. It is hex, and decoding it gives raw bytes instead of readable text.

So at this point the problem became:

```text
metadata hex -> encrypted bytes -> recover plaintext
```

Since this is a CTF flag, we already know the plaintext should start with:

```text
LYKNCTF{
```

That makes repeating-key XOR a really natural thing to try.

## Recovering the XOR key

The ciphertext starts with these bytes:

```text
6d14166842b6ecb6
```

The known plaintext prefix is:

```text
LYKNCTF{
```

XORing those together gives an 8-byte repeating key:

```text
214d5d2601e2aacd
```

It is not a nice printable key, but that does not matter. Repeating those 8 bytes across the whole ciphertext decrypts the metadata into readable text.

Here is the full solve script:

```python
#!/usr/bin/env python3
from binascii import unhexlify

hex_data = (
    "6d14166842b6ecb67622284a65bde8a87e03344564bde3ab"
    "7e1e324b648dc4a87e0a2f4976bdffbd7e0233435ea6cbb45c"
)

ct = unhexlify(hex_data)
known = b"LYKNCTF{"

# The known flag prefix is 8 bytes, which gives the whole repeating XOR key.
key = bytes(c ^ p for c, p in zip(ct[:len(known)], known))

pt = bytes(c ^ key[i % len(key)] for i, c in enumerate(ct))

print(f"key = {key.hex()}")
print(pt.decode())
```

Running it gives:

```text
key = 214d5d2601e2aacd
LYKNCTF{Would_Be_Nice_If_Someone_Grow_Up_One_Day}
```

## Why this works

The image itself was mostly just a carrier. The important data was stored in the PNG metadata, specifically the `Description` field.

That field contained a hex-encoded ciphertext. Because the challenge used the normal LYKNCTF flag format, the first 8 plaintext bytes were known:

```text
LYKNCTF{
```

Using that known plaintext against the first 8 ciphertext bytes recovered the full XOR key. After that, decrypting the rest was just applying the same key repeatedly.

The solve path was:

```text
PNG image
    -> check metadata
    -> find hex in Description
    -> decode hex into bytes
    -> use known flag prefix to recover repeating XOR key
    -> decrypt ciphertext
    -> flag
```

## Final Flag

```text
LYKNCTF{Would_Be_Nice_If_Someone_Grow_Up_One_Day}
```
