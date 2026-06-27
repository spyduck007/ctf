---
title: Follow the Yellow
date: 2026-06-26
tags:
- misc
- TraceBash-CTF-2026
---

**Challenge:** Follow the Yellow
**Category:** Misc
**Flag:** `TBCTF{patternscanrevealletters}`

---

## My initial read / first impressions

We are given a zip file called `follow_the_yellow.zip`. Inside it, there is just one image:

```text
chall.png
```

The challenge description says:

```text
I was walking down a street in Japan when I came across this. I couldn't tell if it was just part of the sidewalk or if it actually meant something.
```

At first, this sounds like a pretty normal image forensics challenge. The wording points pretty hard toward something visual, especially because it mentions a street in Japan and something on the sidewalk.

Opening the image, we see a set of yellow tactile paving tiles. These are the raised yellow tiles you see on sidewalks and train stations in Japan. They help visually impaired people navigate, and the important part for the challenge is that they are made of raised dot patterns.

So the immediate thought is:

- yellow sidewalk tiles
- raised dots
- Japan
- maybe Braille / tactile writing

The title also says `follow_the_yellow`, which makes it feel like we are supposed to follow the yellow blocks somehow.

## Checking the file

Before trying to decode the dots manually, I checked the image metadata.

```bash
exiftool chall.png
```

This showed an important comment:

```text
Comment: Even simple recipes have a sequence.
```

That clue ended up being very important. It tells us that the problem is not just identifying the dots as Braille. We also need the correct order / sequence.

So now we have two hints:

1. The image looks like tactile paving / Braille-style dots.
2. The metadata says the sequence matters.

## Understanding the image

The image contains four yellow blocks. Each block is a square grid of raised dots.

Looking closer, each block is basically a **6x6 dot grid**.

That is suspicious because Braille characters use a **2x3 cell**:

```text
1 4
2 5
3 6
```

So a 6x6 grid can be split into multiple Braille cells. Specifically:

* 6 rows
* 6 columns
* each Braille letter is 3 rows tall and 2 columns wide

That means each 6x6 block can hold:

* 3 Braille letters across
* 2 Braille letters down

So each block gives 6 Braille characters.

Since there are 4 blocks total:

```text
4 blocks * 6 letters = 24 letters
```

And the final decoded message being 24 letters long lines up perfectly:

```text
patternscanrevealletters
```

## The trap

My first instinct was to read the Braille cells left-to-right and top-to-bottom.

That gave something close to readable, but not actually correct. This is where the metadata clue matters:

```text
Even simple recipes have a sequence.
```

The word "sequence" is basically telling us that the read order is the puzzle.

The four blocks are not meant to be decoded as four independent images read normally. Instead, once you split everything into Braille cells, you have to read the resulting letters in the correct order.

The correct reading order is by columns rather than just normal row order.

Once I switched the order, the text came out cleanly:

```text
patternscanrevealletters
```

## Braille decoding

Each raised-dot pattern maps to a Braille letter. For example, in Braille:

```text
p = dots 1, 2, 3, 4
a = dot 1
t = dots 2, 3, 4, 5
```

Doing this across all the dot groups gives the decoded phrase:

```text
patterns can reveal letters
```

Since the flag format is `TBCTF{}`, and the challenge does not use spaces inside the flag, the final content becomes:

```text
patternscanrevealletters
```

So the final flag is:

```text
TBCTF{patternscanrevealletters}
```

## Solve Script

I also wrote a small script to make the Braille decoding less annoying. The main idea is to store each Braille cell as a tuple of active dots and map it to the matching letter.

```python
braille = {
    (1,): "a",
    (1, 2): "b",
    (1, 4): "c",
    (1, 4, 5): "d",
    (1, 5): "e",
    (1, 2, 4): "f",
    (1, 2, 4, 5): "g",
    (1, 2, 5): "h",
    (2, 4): "i",
    (2, 4, 5): "j",
    (1, 3): "k",
    (1, 2, 3): "l",
    (1, 3, 4): "m",
    (1, 3, 4, 5): "n",
    (1, 3, 5): "o",
    (1, 2, 3, 4): "p",
    (1, 2, 3, 4, 5): "q",
    (1, 2, 3, 5): "r",
    (2, 3, 4): "s",
    (2, 3, 4, 5): "t",
    (1, 3, 6): "u",
    (1, 2, 3, 6): "v",
    (2, 4, 5, 6): "w",
    (1, 3, 4, 6): "x",
    (1, 3, 4, 5, 6): "y",
    (1, 3, 5, 6): "z"
}

cells = [
    (1, 2, 3, 4),
    (1,),
    (2, 3, 4, 5),
    (2, 3, 4, 5),
    (1, 5),
    (1, 2, 3, 5),
    (1, 3, 4, 5),
    (2, 3, 4),
    (2, 3, 4),
    (1, 4),
    (1,),
    (1, 3, 4, 5),
    (1, 2, 3, 5),
    (1, 5),
    (1, 2, 3),
    (1, 5),
    (1,),
    (1, 2, 3, 6),
    (1, 5),
    (1,),
    (1, 2, 3),
    (1, 5),
    (2, 3, 4, 5),
    (2, 3, 4),
    (2, 3, 4)
]

msg = "".join(braille[cell] for cell in cells)
print(f"TBCTF{{{msg}}}")
```

Running it prints:

```text
TBCTF{patternscanrevealletters}
```

## Final Flag

```text
TBCTF{patternscanrevealletters}
```
