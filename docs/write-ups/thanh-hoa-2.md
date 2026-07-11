---
title: Thanh Hoa 2
date: 2026-07-06
tags:
- forensics
- LYKNCTF
---

- **Challenge:** Thanh Hoa 2
- **Category:** Forensics
- **Flag:** `LYKNCTF{N3M_CHU4_TH4NH_H04_D4C_S4N_XU_TH4NH}`

---

## My initial read / first impressions

We are given one video file:

```text
lyknctf.mp4
```

The challenge title was basically:

```text
36 Thanh Hoa
```

At first, this looks like a normal video forensics challenge. Since the file is an MP4, my first thought was to check the boring stuff first: metadata, extra streams, strings, and anything appended after the real video data.

The `36` part also felt intentional. Thanh Hoa is a Vietnamese province, and `36` is associated with Thanh Hoa license plates, so I kept that in mind as a possible clue. But the actual solve came from the file structure first.

## Checking the MP4

I started with the usual quick checks:

```bash
file lyknctf.mp4
exiftool lyknctf.mp4
ffprobe lyknctf.mp4
strings -a lyknctf.mp4 | head
```

Nothing in the normal MP4 metadata directly gave the flag.

So the next step was to check whether there were extra files hidden inside or appended to the MP4. Running a carving / signature check showed that the video had more than just MP4 data in it.

There were embedded files including:

```text
attached.png
contact.jpg
hidden.zip
```

The ZIP was the most obviously suspicious one, but it was encrypted. Listing it showed a `flag.txt`, but extracting it required a password.

So at that point the problem became:

```text
find the ZIP password somewhere else in the MP4
```

## Looking at the extracted images

The extracted images looked like normal challenge bait at first. I also pulled out a few video frames around the interesting-looking parts, but the visible frames were not enough by themselves.

Since the ZIP password had to be hidden somewhere, I checked the images more carefully instead of only looking at them visually.

The important file ended up being:

```text
attached.png
```

Normal metadata still did not give the password, so I checked for basic LSB steganography.

## Extracting the LSB message

For the PNG, I tested the least significant bits of the RGB channels. The trick was not even across the whole image. The message was hidden in the first row of pixels.

This script extracts the first-row RGB LSB bits and converts them into bytes:

```python
#!/usr/bin/env python3
from PIL import Image

img = Image.open("attached.png").convert("RGB")
pixels = img.load()
width, height = img.size

bits = []

# The password is stored in the RGB LSBs across the first row.
for x in range(width):
    r, g, b = pixels[x, 0]
    bits.append(r & 1)
    bits.append(g & 1)
    bits.append(b & 1)

out = bytearray()
for i in range(0, len(bits) - 7, 8):
    byte = 0
    for bit in bits[i:i + 8]:
        byte = (byte << 1) | bit

    if byte == 0:
        break

    out.append(byte)

print(out.decode(errors="ignore"))
```

Running it gives:

```text
NEMCHUATHANHHOA
```

That immediately lines up with the title. `Nem chua Thanh Hoa` is the Thanh Hoa-specific clue, so this looked exactly like the intended password and not just random decoded garbage.

## Decrypting the ZIP

Using the recovered password on the encrypted ZIP worked:

```bash
unzip hidden.zip
# password: NEMCHUATHANHHOA
```

Inside was:

```text
flag.txt
```

Reading it gave:

```text
LYKNCTF{N3M_CHU4_TH4NH_H04_D4C_S4N_XU_TH4NH}
```

## Why this works

The MP4 was basically a container hiding a few extra files after / inside the video data. The ZIP held the final flag, but it was encrypted, so the real forensics step was finding the password.

The password was hidden with simple image steganography:

```text
attached.png
    -> first row of pixels
    -> RGB least significant bits
    -> ASCII text
    -> NEMCHUATHANHHOA
```

Then that password decrypts the ZIP:

```text
hidden.zip
    -> flag.txt
    -> LYKNCTF{N3M_CHU4_TH4NH_H04_D4C_S4N_XU_TH4NH}
```

So the full solve path was:

1. Inspect the MP4 instead of only watching it.
2. Carve / extract embedded files.
3. Notice the encrypted ZIP.
4. Look for the password in the extracted images.
5. Decode RGB LSBs from `attached.png`.
6. Use `NEMCHUATHANHHOA` as the ZIP password.
7. Read `flag.txt`.

## Final Flag

```text
LYKNCTF{N3M_CHU4_TH4NH_H04_D4C_S4N_XU_TH4NH}
```
