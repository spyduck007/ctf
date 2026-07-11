---
title: Static
date: 2026-07-06
tags:
- misc
- LYKNCTF
---

- **Challenge:** Static
- **Category:** Misc
- **Flag:** `LYKNCTF{DONTGO}`

---

## My initial read / first impressions

The challenge gives a YouTube link and then this description:

```text
H..Hey... don’t leave me yet :( Don’t you find it all romantic, the way things used to be? Right from the moment I started making this challenge, I kept thinking about Semaphore. Classic, ecstatic, it’s magic.
```

The hint makes the important part very direct:

```text
This challenge is about Flag Semaphore.
```

So this was not really about hidden metadata, YouTube comments, subtitles, or anything like that. The solve was to look at the actual video and decode the flag semaphore being shown.

## The important clue

Flag semaphore encodes letters using the positions of two flags. Each pose maps to one letter.

The challenge also tells us exactly how the final answer should be cleaned up:

```text
FLAG FORMAT: LYKNCTF{WORD}
If a word is repeated, keep only one occurrence of it.
All letters in the word must be uppercase.
Remove all whitespace and anything that is not a letter.
```

That means even if the decoded message has spaces, punctuation, or repeated words, the final flag needs to be normalized before submitting.

## Decoding the video

In the video, there is a part where the character is making flag semaphore poses. Since semaphore is based on arm positions, I paused through that section and matched each pose against a semaphore alphabet chart.

Reading the poses gives:

```text
DONT GO
```

Or written normally:

```text
DON'T GO
```

The apostrophe is not a letter, and the space also has to be removed because of the flag-format instructions.

So the cleaned message becomes:

```text
DONTGO
```

## Why this works

The challenge title and description are basically nudging toward the music video, but the actual hint removes most of the guessing. Once we know it is flag semaphore, the solve is just visual decoding:

1. Find the semaphore section in the video.
2. Pause on each distinct pose.
3. Match the flag positions to the semaphore alphabet.
4. Decode the phrase as `DON'T GO`.
5. Remove non-letters and whitespace.
6. Uppercase everything for the flag.

There is also a small formatting trap here. The decoded phrase is two words with an apostrophe, but the final submitted value should only contain letters.

## Flag

```text
LYKNCTF{DONTGO}
```
