---
title: Inferior Student
date: 2026-07-06
tags:
- rev
- LYKNCTF
---

- **Challenge:** Inferior Student
- **Category:** Rev
- **Flag:** `LYKNCTF{Im_At_The_PayPhone_Tryin_To_Home_Allof_My_change_1_Spent_0n_u_Where_have_ThE_T1m3S_G0n3_B4bY_Its_Wr0nG_wh3rE_aRe_Th3_Pl4nS_W3_M4d3_F0r_2}`

---

## My initial read / first impressions

The challenge description was just:

```text
Nothing Stay
```

We are given two files:

```text
chall.exe
challl.py
```

At first this looked like it might be a normal Windows rev challenge, but the Python file made the direction pretty obvious. The `.exe` was a packaged Python program, and `challl.py` was basically the same thing but in a very ugly obfuscated form.

So instead of treating this like a normal native Windows binary, I focused on the Python loader. The file was full of weird Unicode variable names, anti-debug checks, encrypted blobs, and `marshal` / `zlib` / crypto imports.

That usually means the actual checker is hidden as encrypted Python bytecode and executed dynamically.

## Understanding the loader

The first annoying part is that the loader computes a one-byte environment value. I called it the anti-debug byte.

It checks things like:

- whether a Python tracer is attached
- whether debugging modules/tools are loaded
- whether the process is running under suspicious timing conditions
- Windows debugger APIs when running on Windows
- Linux `ptrace` / `/proc`-style checks when running on Linux

That byte is then mixed into the decryption process. If the byte is wrong, the later stages decrypt to garbage.

The important realization was that this byte is only one byte, so there are only 256 possible values. There was no need to perfectly emulate every anti-debug check. I could just brute force it.

For the normal no-debugger path, the correct value ended up being:

```text
0x00
```

With that value, all seven encrypted stages decrypted cleanly.

## Decrypting the stages

The loader stores several encrypted blobs. Each blob has the pieces needed to decrypt another Python payload. The general shape is:

```text
key / nonce / ciphertext / tag-ish data
```

After trying the anti-debug byte values, `0x00` produced valid compressed / marshalled Python code objects.

The big stage was Python 3.12 bytecode. That was slightly annoying because I was not relying on normal decompilers to fully reconstruct perfect source. But I did not actually need perfect source. I only needed the final flag check.

Once the bytecode was decoded enough to inspect constants and the final crypto call, the important part became clear:

```text
input -> ChaCha20 encryption -> compare against hardcoded ciphertext
```

So the binary was not doing a complex symbolic check at the very end. It was encrypting the user's input with a fixed ChaCha20 key and nonce, then comparing the result to a fixed ciphertext.

That means the solve is just the inverse:

```text
decrypt hardcoded ciphertext with the same ChaCha20 key and nonce
```

## The final ChaCha20 layer

The final checker uses Python's `cryptography` ChaCha20 implementation.

The recovered key was:

```python
key = bytes([
    169,136,202,9,54,119,85,248,230,132,231,205,5,89,178,140,
    14,235,26,63,142,119,14,89,255,117,65,254,142,100,126,151
])
```

The recovered nonce was:

```python
nonce = bytes([
    31,158,216,188,255,230,52,234,217,230,208,247,34,82,106,72
])
```

And the hardcoded ciphertext was:

```text
886c6a98519bf55c648b224bf9dd3f9ab0223d1b480376751604ff0c
b1750740a52f08a4b20d42b9fe1c41d4b1ef7ca8e19709960dd3d386
454c72ba6d9f262600e6d85456e9ba43f36a69ffc21fb28f29b46f6e6
95dd88fe50a9aff3167b986707d607bfa3546b02e08dc7e75316ef83c
047e60c17280fd6b8b0ecba485be5c13124b8243bd217be8021cd6ffc
ab502e7
```

Since ChaCha20 is a stream cipher, encryption and decryption are the same operation. Applying the keystream to the ciphertext gives the original input, which is the flag.

## Solution Script

Here is the final clean solve script I used.

```python
#!/usr/bin/env python3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

key = bytes([
    169, 136, 202, 9, 54, 119, 85, 248,
    230, 132, 231, 205, 5, 89, 178, 140,
    14, 235, 26, 63, 142, 119, 14, 89,
    255, 117, 65, 254, 142, 100, 126, 151,
])

nonce = bytes([
    31, 158, 216, 188, 255, 230, 52, 234,
    217, 230, 208, 247, 34, 82, 106, 72,
])

ct = bytes.fromhex(
    "886c6a98519bf55c648b224bf9dd3f9ab0223d1b480376751604ff0c"
    "b1750740a52f08a4b20d42b9fe1c41d4b1ef7ca8e19709960dd3d386"
    "454c72ba6d9f262600e6d85456e9ba43f36a69ffc21fb28f29b46f6e6"
    "95dd88fe50a9aff3167b986707d607bfa3546b02e08dc7e75316ef83c"
    "047e60c17280fd6b8b0ecba485be5c13124b8243bd217be8021cd6ffc"
    "ab502e7"
)

dec = Cipher(algorithms.ChaCha20(key, nonce), mode=None).decryptor()
flag = dec.update(ct) + dec.finalize()

print(flag.decode())
```

Running it prints:

```text
LYKNCTF{Im_At_The_PayPhone_Tryin_To_Home_Allof_My_change_1_Spent_0n_u_Where_have_ThE_T1m3S_G0n3_B4bY_Its_Wr0nG_wh3rE_aRe_Th3_Pl4nS_W3_M4d3_F0r_2}
```

## Why this works

The challenge is mostly meant to waste time with layers:

1. PyInstaller / packaged Python instead of a clean script.
2. Heavy Python obfuscation with unreadable variable names.
3. Anti-debug checks mixed into a one-byte environment value.
4. Multiple encrypted marshal stages.
5. A final bytecode stage that hides the real checker.

But the final checker is just a fixed ChaCha20 comparison. Once the key, nonce, and target ciphertext are recovered, there is nothing left to brute force.

The full chain is:

```text
chall.exe / challl.py
    -> identify the obfuscated Python loader
    -> brute force the one-byte anti-debug value
    -> decrypt the marshal/zlib stages
    -> inspect the final Python bytecode
    -> recover ChaCha20 key, nonce, and ciphertext
    -> decrypt ciphertext
    -> flag
```

## Flag

```text
LYKNCTF{Im_At_The_PayPhone_Tryin_To_Home_Allof_My_change_1_Spent_0n_u_Where_have_ThE_T1m3S_G0n3_B4bY_Its_Wr0nG_wh3rE_aRe_Th3_Pl4nS_W3_M4d3_F0r_2}
```
