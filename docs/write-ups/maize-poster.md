---
title: Maize Poster
date: 2026-11-20
tags:
- crypto
- WolvCTF-2026
---

- **Challenge:** Maize Poster
- **Category:** Crypto
- **Flag:** `wctf{r0t13_1n_th3_blu3}`

---

## My initial read / first impressions

The challenge description says:

```text
I just got a new poster for my dorm! Though whoever made this put a secret message into it. If you squint really closely at the pixels you might find it.
```

We're given `dis.tar.gz`, which only has `poster.png` inside:

```bash
tar -tzf dis.tar.gz
tar -xzf dis.tar.gz
file poster.png
```

It's a 960x740 PNG of a Michigan poster, with the big blue M on a maize background. Nothing looks wrong with it when you open it normally, but the description is pretty specific about looking at the pixels, so I started checking the actual RGB values.

## Checking the colors

There are only three different RGB colors in the entire image:

```text
(255, 203, 5)  : 471504 pixels
(0, 39, 76)   : 238793 pixels
(0, 39, 77)   : 103 pixels
```

The first two are the normal maize and blue colors. The third one is almost exactly the same as the dark blue, except its blue channel is `77` instead of `76`.

That one-bit difference looked like LSB steganography. Changing the last bit of a color value barely changes how it looks, but it gives you somewhere to store a bit of data.

I also checked where those 103 slightly different blue pixels were. Every single one is in the first row of the image. The rest of that row uses `(0, 39, 76)`, so reading the lowest bit of the blue channel from left to right gives a string of zeroes and ones.

## Decoding the first row

The first eight bits are:

```text
01101010
```

That's `j` in ASCII. The next bytes start spelling `jpgs{`, which looks a lot like a flag prefix after some kind of substitution.

Reading 184 bits (23 bytes) from that first row gives:

```text
jpgs{e0g13_1a_gu3_oyh3}
```

`jpgs` becomes `wctf` under ROT13, so I decoded the whole string with ROT13:

```text
wctf{r0t13_1n_th3_blu3}
```

## Solution script

This reads the blue-channel LSBs from the first row, turns each group of eight bits into a character, and stops at the closing brace. Then it applies ROT13.

```python
#!/usr/bin/env python3
from codecs import decode
from PIL import Image

img = Image.open("poster.png")
message = ""

for x in range(0, img.width, 8):
    bits = "".join(str(img.getpixel((x + i, 0))[2] & 1) for i in range(8))
    char = chr(int(bits, 2))
    message += char
    if char == "}":
        break

print(message)
print(decode(message, "rot_13"))
```

Run it with `poster.png` in the same directory (you'll need Pillow installed):

```bash
python3 solve.py
```

```text
jpgs{e0g13_1a_gu3_oyh3}
wctf{r0t13_1n_th3_blu3}
```

## Why this works

The poster uses the blue channel's least significant bit to hide a message in the top row. Blue values of `76` and `77` look basically identical in the image, but their last bits are different: `0` and `1`.

Those bits form ASCII text, and that text has another layer of encoding with ROT13. The flag is there in the pixels without changing what the poster looks like.

## Final flag

```text
wctf{r0t13_1n_th3_blu3}
```
