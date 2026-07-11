---
title: I HATE THIS APP REVENGE
date: 2026-07-06
tags:
- rev
- LYKNCTF
---

- **Challenge:** I HATE THIS APP REVENGE
- **Category:** Rev
- **Flag:** `LYKNCTF{alolanvulpix}`

---

## My initial read / first impressions

The challenge gives us two files:

```text
726471288_122216388452484307_639451856029278247_n.enc.bin
fuoverflow_learning.rar
```

The description says someone tried to download an image gallery, but instead of getting actual images they only got encrypted text. So the goal is pretty clearly:

```text
encrypted gallery file + app archive -> reverse the app -> decrypt the image -> identify the character
```

The `.enc.bin` file does not start with normal image magic bytes like JPEG or PNG. So there was no point trying to rename it or run normal file carving on it. The app had to contain the decryption logic.

## Extracting the app

I extracted the `fuoverflow_learning.rar` archive and started looking through the app files. Since this was an app challenge, the first useful step was just searching for crypto-looking strings and secrets.

Some of the interesting strings in the binary were:

```text
HMAC verification failed
FUO_PASS_SECRET
FIXED_ENCRYPTION_KEY
```

That was a pretty good sign that the app was not using some random homebrew XOR. It had actual encryption logic, and the important part was probably hidden behind one of those constants / environment variables.

The useful hardcoded fallback key was:

```text
H}3t%^nDw5F?cWj-XAH!Dj8AakaD9y9M
```

It is exactly 32 bytes, which lines up perfectly with AES-256.

## Understanding the encrypted file format

Looking at the encrypted file, the first bytes were not ciphertext for the image itself. The structure ended up being:

```text
8-byte nonce || 4-byte counter || AES-CTR ciphertext
```

So the first 12 bytes are AES-CTR setup data, and everything after that is the encrypted image data.

This also explains why the file did not need padding. AES-CTR turns AES into a stream cipher mode, so it can decrypt data of any length. If we have the key, nonce, and counter, we can just generate the same keystream and XOR the ciphertext back into the original image.

The important pieces were:

```text
key        = H}3t%^nDw5F?cWj-XAH!Dj8AakaD9y9M
nonce      = encrypted_file[0:8]
counter    = encrypted_file[8:12]
ciphertext = encrypted_file[12:]
```

## Decrypting the image

This was the solve script I used to recover the image:

```python
from pathlib import Path
from Crypto.Cipher import AES

ENC_FILE = "726471288_122216388452484307_639451856029278247_n.enc.bin"
OUT_FILE = "recovered.jpg"

key = b"H}3t%^nDw5F?cWj-XAH!Dj8AakaD9y9M"
enc = Path(ENC_FILE).read_bytes()

nonce = enc[:8]
counter = int.from_bytes(enc[8:12], "big")
ciphertext = enc[12:]

cipher = AES.new(
    key,
    AES.MODE_CTR,
    nonce=nonce,
    initial_value=counter,
)

plaintext = cipher.decrypt(ciphertext)
Path(OUT_FILE).write_bytes(plaintext)

print(plaintext[:16])
print(f"wrote {OUT_FILE}")
```

Running it gave a valid JPEG header:

```text
ff d8 ff
```

So the decrypted output was a real image:

```text
recovered.jpg
```

## Identifying the character

After opening the recovered image, the character was the cute white fox-looking Pokemon with the icy blue eyes and curled hair/fur.

That character is **Alolan Vulpix**.

The challenge wants the answer in lowercase with no spaces, so the character name becomes:

```text
alolanvulpix
```

## Flag

```text
LYKNCTF{alolanvulpix}
```
