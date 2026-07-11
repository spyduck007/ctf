---
title: World Cup 1
date: 2026-07-06
tags:
- forensics
- LYKNCTF
---

- **Challenge:** World Cup 1
- **Category:** Forensics
- **Flag:** `LYKNCTF{Argentina3-2CaboVerde}`

---

## My initial read / first impressions

We are given a PNG image showing a fake World Cup match result:

```text
Argentina 3 - 2 Cabo Verde
AET
```

The flavor text talks about waking up at 5 AM Vietnam time to watch Messi, but instead seeing Cabo Verde fight all the way through 120 minutes against the defending champions.

At first, this looks like it could maybe be some sports OSINT thing because of the teams, the time zone, and Messi. But the category is **Forensics**, so I started with the file itself instead of trying to research some fake match history.

For image forensics, I usually start with the boring checks:

```bash
file worldcup1_challenge.png
exiftool worldcup1_challenge.png
strings -a worldcup1_challenge.png | head
binwalk worldcup1_challenge.png
```

The visible image already gives the score, but not the exact flag format. So the next step was checking whether the PNG was hiding anything in metadata or pixel data.

## Checking the metadata

`exiftool` gave the useful clue right away:

```text
Flag_Hint: Look deeper in the red pixels
Comment: The score was 3-2 after extra time
```

That basically tells us two things:

```text
red pixels
3-2 after extra time
```

The score confirms the visible part of the image, but the real instruction is to look at the red channel. In image stego challenges, that usually means checking the least significant bits of a color channel.

## Extracting the red-channel LSBs

Since the hint specifically said red pixels, I extracted the least significant bit from the red value of each pixel and grouped the bits into bytes.

This was the script I used:

```python
#!/usr/bin/env python3
from PIL import Image

img = Image.open("worldcup1_challenge.png").convert("RGB")

bits = []
for y in range(img.height):
    for x in range(img.width):
        r, g, b = img.getpixel((x, y))
        bits.append(r & 1)

out = bytearray()
for i in range(0, len(bits) - 7, 8):
    byte = 0
    for bit in bits[i:i + 8]:
        byte = (byte << 1) | bit
    out.append(byte)

print(out[:100])
```

Running it printed the flag near the start of the decoded bytes:

```text
LYKNCTF{Argentina3-2CaboVerde}
```

So there was no need to mess with every color channel or try complicated stego tools. The metadata was basically pointing straight at the correct channel.

## Why this works

Each pixel has RGB values, and each color value is stored as a number. Changing the last bit of one color channel usually changes the image so slightly that it is visually impossible to notice.

So the challenge hid the message like this:

```text
worldcup1_challenge.png
    -> red channel values
    -> least significant bit of each red value
    -> regroup bits into bytes
    -> ASCII text
    -> LYKNCTF{Argentina3-2CaboVerde}
```

The flavor text and scoreboard helped confirm the final flag text, but the actual solve path was metadata plus red-channel LSB extraction.

## Final Flag

```text
LYKNCTF{Argentina3-2CaboVerde}
```
