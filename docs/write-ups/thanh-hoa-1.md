---
title: Thanh Hoa 1
date: 2026-07-06
tags:
- forensics
- LYKNCTF
---

- **Challenge:** Thanh Hoa 1
- **Category:** Forensics
- **Flag:** `LYKNCTF{NGU01_TH4NH_H04_4N_R4U_M4_PH4_DU0NG_T4U}`

---

## My initial read / first impressions

We are given one video file:

```text
lyknctf.mp4
```

The challenge title / prompt was basically:

```text
36 Thanh Hoa
```

Since this was a forensics challenge with an MP4, I started with the usual boring checks first: metadata, streams, strings, embedded files, and anything appended after the real video data.

The `36` part also seemed intentional because Thanh Hoa is associated with the number 36 in Vietnam. So I kept the Thanh Hoa theme in mind, but I did not want to overthink the clue before actually inspecting the file.

## Checking the MP4

I started with the normal MP4 checks:

```bash
file lyknctf.mp4
exiftool lyknctf.mp4
ffprobe lyknctf.mp4
strings -a lyknctf.mp4 | head
```

Nothing in the normal metadata immediately gave the flag.

The next step was to check whether the file had anything hidden inside it. Since MP4 files are just containers, it is always worth checking for appended archives or extra signatures instead of only watching the video.

Running a carving / signature check showed that there was a ZIP archive hidden at the end of the MP4:

```bash
binwalk lyknctf.mp4
```

Extracting / carving the ZIP gave:

```text
hidden.zip
```

Listing the archive showed that it contained a `flag.txt`, but the ZIP was encrypted. So the solve was clearly split into two parts:

```text
1. Find the ZIP hidden in the MP4.
2. Find the password somewhere else in the challenge file.
```

## The encrypted ZIP

Trying to unzip it directly failed because it needed a password:

```bash
unzip hidden.zip
```

The important thing here is that the ZIP was not the whole answer. It was just the locked box. Since the challenge gave an MP4 and not only a random archive, the password was probably hidden in one of the media streams.

At that point I checked the video frames and the audio separately. The visible frames did not immediately give a useful password, so I moved to the audio.

## Looking at the audio

For audio stego, the first thing I like to check is the spectrogram. A lot of CTF audio challenges hide text visually in the frequency domain, and this challenge was doing exactly that.

I extracted the audio and generated a spectrogram:

```bash
ffmpeg -i lyknctf.mp4 -vn audio.wav
sox audio.wav -n spectrogram -o spectrogram.png
```

Looking at the spectrogram showed repeated text. The password was:

```text
RAUMAPHATAU
```

This also matches the Thanh Hoa theme. `Rau má pha đậu` is a Thanh Hoa-related phrase, so it did not look like random spectrogram noise. It looked like the intended ZIP password.

## Decrypting the ZIP

Using the recovered password on the ZIP worked:

```bash
unzip hidden.zip
# password: RAUMAPHATAU
```

Inside was:

```text
flag.txt
```

Reading it gave:

```text
LYKNCTF{NGU01_TH4NH_H04_4N_R4U_M4_PH4_DU0NG_T4U}
```

## Why this works

The MP4 was hiding an encrypted ZIP after the actual media data. The final flag was inside `flag.txt`, but the archive could not be opened until the password was recovered.

The password was not in normal metadata or strings. It was hidden visually inside the audio spectrogram:

```text
lyknctf.mp4
    -> hidden.zip appended / embedded
    -> hidden.zip contains encrypted flag.txt
    -> audio spectrogram shows RAUMAPHATAU
    -> RAUMAPHATAU decrypts the ZIP
    -> flag.txt contains the flag
```

So the full solve path was:

1. Inspect the MP4 instead of only watching it.
2. Carve out the hidden ZIP.
3. Notice that the ZIP is encrypted.
4. Extract the audio from the MP4.
5. Generate a spectrogram.
6. Read the password `RAUMAPHATAU` from the spectrogram.
7. Use that password to unzip `hidden.zip`.
8. Read `flag.txt`.

## Flag

```text
LYKNCTF{NGU01_TH4NH_H04_4N_R4U_M4_PH4_DU0NG_T4U}
```
