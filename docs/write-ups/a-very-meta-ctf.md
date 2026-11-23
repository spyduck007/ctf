---
title: A Very Meta CTF
date: 2026-11-20
tags:
- forensics
- WolvCTF-2026
---

- **Challenge:** A Very Meta CTF
- **Category:** Forensics
- **Flag:** `wctf{th1s_1s_4_fl4g_IE0j32e}`

---

## My initial read / first impressions

The challenge description says:

```text
Ten pictures were found on a pirate's computer. Can you recover the message hidden in them?
```

We get `dist.tar.gz`. Listing the archive shows a description file and ten PNGs:

```bash
tar -tzf dist.tar.gz
```

```text
description.md
pictures/eight.png
pictures/five.png
pictures/four.png
pictures/nine.png
pictures/one.png
pictures/seven.png
pictures/six.png
pictures/ten.png
pictures/three.png
pictures/two.png
```

The filenames are numbers written out as words, but the archive lists them alphabetically. Since the challenge is literally called *A Very Meta CTF*, I checked the image metadata first instead of messing with the pixels.

## Checking the metadata

After extracting the archive, I ran `exiftool` on one of the images:

```bash
tar -xzf dist.tar.gz
exiftool -UserComment pictures/one.png
```

```text
User Comment                    : 735f
```

That looks like hex. Decoding it gives:

```python
>>> bytes.fromhex("735f").decode()
's_'
```

So the `UserComment` field is holding pieces of the message. I checked the rest and got more hex strings. The first few files in alphabetical order decode to `wc`, `tf`, `{t`, which is already the start of a flag.

## Putting the pieces together

I used a short Python script to pull the comment from every image, hex-decode it, and join the results in filename order. No need to sort the number words numerically; alphabetical order is what gives the flag.

## Solution script

```python
#!/usr/bin/env python3
from pathlib import Path
import subprocess

parts = []

for path in sorted(Path("pictures").glob("*.png")):
    hex_data = subprocess.check_output(
        ["exiftool", "-s3", "-UserComment", str(path)],
        text=True,
    ).strip()

    piece = bytes.fromhex(hex_data).decode()
    print(f"{path.name}: {hex_data} -> {piece}")
    parts.append(piece)

print("".join(parts))
```

Running it after extracting the archive:

```bash
python3 solve.py
```

```text
eight.png: 7763 -> wc
five.png: 7466 -> tf
four.png: 7b74 -> {t
nine.png: 6831 -> h1
one.png: 735f -> s_
seven.png: 3173 -> 1s
six.png: 5f34 -> _4
ten.png: 5f66 -> _f
three.png: 6c34 -> l4
two.png: 675f4945306a3332657d -> g_IE0j32e}
wctf{th1s_1s_4_fl4g_IE0j32e}
```

## Why this works

Each PNG has an EXIF `UserComment` containing hex-encoded ASCII. The comments are split across ten files, and sorting the filenames alphabetically puts the chunks in the right order. The images themselves don't need any stego extraction.

## Final flag

```text
wctf{th1s_1s_4_fl4g_IE0j32e}
```
