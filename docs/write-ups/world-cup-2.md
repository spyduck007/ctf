---
title: World Cup 2
date: 2026-07-06
tags:
- forensics
- LYKNCTF
---

- **Challenge:** World Cup 2
- **Category:** Forensics
- **Flag:** `LYKNCTF{RespectToCaboVerde}`

---

## My initial read / first impressions

We are given an image about Cabo Verde being eliminated from the World Cup:

```text
Cape Verde are out of the World Cup
ELIMINATED
```

The flavor text mentions waking up at 5 AM Vietnam time to watch Messi, but instead seeing Cabo Verde survive against the defending champions for 120 minutes.

At first this looks like it could be an OSINT-ish sports clue, especially because the text mentions time zones, Messi, Cabo Verde, and the defending champions. But since the category is **Forensics**, I did not want to overthink the story too early.

For image forensics, my first checks are always the boring ones:

```bash
file worldcup2_challenge.png
exiftool worldcup2_challenge.png
strings -a worldcup2_challenge.png | head
binwalk worldcup2_challenge.png
```

The important thing was not hidden in the visible image. The image was being used as a container.

## Checking the file structure

Running `binwalk` showed that there was a ZIP archive appended after the normal image data.

That is a super common forensics trick: the file opens normally as an image because image viewers stop parsing once the image is done, but extra bytes after the image can still contain another whole file.

So the real solve path became:

```text
image
  -> extra appended data
  -> ZIP archive
  -> hidden text file
```

## Extracting the appended ZIP

There are a couple ways to pull it out. The easiest is just letting `binwalk` carve it:

```bash
binwalk -e worldcup2_challenge.png
```

After extraction, the carved files contained:

```text
flag_hidden.txt
```

You could also do this with `foremost`, `7z`, or by manually cutting the file at the ZIP header if needed. The key signature to look for is:

```text
PK\x03\x04
```

That marks the start of a ZIP local file header.

## Reading the hidden file

Once the ZIP was extracted, there was no password or second layer. Reading the hidden text file gave the flag directly:

```bash
cat flag_hidden.txt
```

Output:

```text
LYKNCTF{RespectToCaboVerde}
```

## Why this works

The image itself is valid, so just opening it normally only shows the soccer graphic. But the file has another archive attached to the end of it.

Most image parsers do not care about trailing bytes after the actual image data, so the file can be both:

```text
a normal viewable image
```

and:

```text
a carrier for an appended ZIP archive
```

at the same time.

So the intended trick was basically to stop looking at the picture and inspect the file bytes.

The full path was:

```text
worldcup2_challenge.png
    -> binwalk finds appended ZIP data
    -> extract the ZIP
    -> flag_hidden.txt
    -> LYKNCTF{RespectToCaboVerde}
```

## Final Flag

```text
LYKNCTF{RespectToCaboVerde}
```
