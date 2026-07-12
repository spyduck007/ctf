---
title: Terminal Diff
date: 2026-07-11
tags:
- misc
- BroncoCTF-2026
---

- **Challenge:** Terminal Diff
- **Category:** Misc
- **Flag:** `bronco{resizing_the_whole_world}`

---

## My initial read / first impressions

The challenge description says:

```text
I used to be too big picture, never focusing on the details (keeping track of like 90 things at once). Then, I starting looking into things a little bit too much (this phase only lasted like 7 days). Nowadays though, I am primed to look at things with just the right width (and height too). Anyways, here's the flag! You should be able to read it just fine, as long as you align with my mindset.
```

The attached file was just a giant mess of `/`, `\`, `_`, arrows, carets, and even a random-looking piece of Unicode art in the middle. Opening it normally was not very useful because everything appeared on one huge line.

That made the title **Terminal Diff** and the wording of the prompt feel pretty important. This was probably not encrypted text. It was text that needed to be displayed with the correct terminal dimensions.

The phrases that stood out were:

```text
keeping track of like 90 things at once
this phase only lasted like 7 days
primed to look at things with just the right width (and height too)
align with my mindset
```

So my first thought was that the file was a flattened terminal screen, and the goal was to recover the original width/height.

## Finding the right dimensions

Since the file looked like one long flattened line, I checked its length and factored it:

```python
from pathlib import Path

s = Path("flag.txt").read_text().rstrip("\n")
print(len(s))

for w in range(1, len(s) + 1):
    if len(s) % w == 0:
        print(w, len(s) // w)
```

This gave a useful factor pair:

```text
97 x 35
```

That immediately matched the clue. The prompt says the author is now **primed** to look at things with the right width, and `97` is a prime number. It is also close to the "like 90 things at once" hint, so it made sense as a terminal width.

At this point, I wrapped the file at width 97:

```python
from pathlib import Path

s = Path("flag.txt").read_text().rstrip("\n")
w = 97

for i in range(0, len(s), w):
    print(s[i:i+w])
```

Now the mess turned back into a readable terminal-style image.

## Reading the flag

After wrapping at 97 columns, the text forms a big rectangular ASCII layout. The flag is not written left-to-right in one normal line, though. There are arrows and alignment markers showing how to follow the pieces around the rectangle.

The important path reads:

```text
bronco{r
esizing
_the_
whole_world}
```

Putting those chunks together gives:

```text
bronco{resizing_the_whole_world}
```

## Why this works

The trick is that the file is not really encoded in the normal crypto sense. The information is already there, but the terminal width is wrong.

If the terminal or text editor shows the file as one long line, the image is destroyed. Once the data is split into rows of 97 characters, the intended drawing appears again.

So the actual solve is:

```text
flattened terminal output
    -> check total length
    -> factor dimensions
    -> notice prime-ish width clue
    -> wrap at 97 columns
    -> follow the aligned ASCII path
    -> read the flag
```

The challenge is basically a terminal-resizing puzzle, which also fits the flag perfectly.

## Solution script

This is the small script I used to display the file correctly:

```python
from pathlib import Path

s = Path("flag.txt").read_text().rstrip("\n")
width = 97

assert len(s) % width == 0

for i in range(0, len(s), width):
    print(s[i:i + width])
```

## Flag

```text
bronco{resizing_the_whole_world}
```
