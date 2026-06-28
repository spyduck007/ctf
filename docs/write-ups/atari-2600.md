---
title: Atari 2600
date: 2026-06-26
tags:
- misc
- V1T-CTF-2026
---

- **Challenge:** Atari 2600
- **Category:** Misc
- **Flag:** `V1T{O_O}`

---

## My initial read / first impressions

We are given a single file:

```text
v1t.bas.bin
```

At first, the `.bas.bin` filename made it look like it could be some weird BASIC program or maybe a compiled game. Running normal checks on it did not show any obvious text or strings that looked like a flag.

The file is exactly `4096` bytes, which is a big hint. A 4KB binary with this kind of structure is very likely an **Atari 2600 ROM**.

So instead of treating it like a normal executable, I started looking at it as a 6502 program mapped into Atari 2600 cartridge memory.

For Atari 2600 4KB ROMs, the ROM usually gets mapped at:

```text
$F000 - $FFFF
```

So file offset `0x000` corresponds to address `$F000`.

## Looking through the ROM

Since this is a game challenge and the prompt says:

```text
Can you get that prize ?
```

I assumed the flag would probably appear after triggering some in-game condition, like touching a prize or reaching a certain state.

But instead of playing the game manually, I looked for suspicious code paths in the ROM. One thing that stood out was this code around `$F50A`:

```asm
F50A: A5 D7
F50C: D0 07
F50E: 20 62 F5
F511: A9 01
F513: 85 D7
```

The important instruction is:

```asm
JSR $F562
```

That means the game calls a subroutine at `$F562`.

This looked very suspicious because it was guarded by a variable at `$D7`, almost like the game only wants to run this routine once. That already made it feel like a “you got the prize” or “show the reward” routine.

## The suspicious drawing routine

At `$F562`, the code turns into a giant list of repeated instructions like this:

```asm
A2 00
A0 01
A9 00
20 78 F2
```

And then again:

```asm
A2 00
A0 01
A9 02
20 78 F2
```

This pattern repeats a ton of times.

Translated into assembly, each block is basically:

```asm
LDX #$00
LDY #$01
LDA #$00
JSR $F278
```

The values change each time, but the structure stays the same.

That made the routine pretty easy to understand. It is calling `$F278` over and over with different `A` and `Y` values.

Looking at `$F278`, it behaves like a pixel / playfield plotting function. The value in `A` acts like an x-coordinate, and `Y` acts like a row. So the routine at `$F562` is not doing complex logic. It is literally drawing pixels.

That was the big giveaway.

## Decoding the pixels

Instead of trying to emulate the Atari 2600, I extracted every repeated call from `$F562`.

The format was:

```text
A2 00 A0 YY A9 XX 20 78 F2
```

So each block gives one plotted pixel:

- `XX` is the x-coordinate
- `YY` is the y-coordinate

After extracting all the `(x, y)` pairs and printing them as a grid, the first few rows looked like this:

```text
#.#..#..###..##.###.....###.##.
#.#.##...#..##..#.#.....#.#..##
.#...#...#...##.###.###.###.##.
```

At first it looks kind of ugly, but if you split it into 3-wide characters with a 1-column gap, it becomes readable:

```text
#.#  .#.  ###  .##  ###  ...  ###  ##.
#.#  ##.  .#.  ##.  #.#  ...  #.#  .##
.#.  .#.  .#.  .##  ###  ###  ###  ##.
```

Reading the tiny 3x3 font gives:

```text
V1T{O_O}
```

So the hidden prize was literally drawn into the Atari playfield.

## Solution Script

Here is the final script I used to extract the plotted pixels and decode the message.

```python
from pathlib import Path

rom = Path("v1t.bas.bin").read_bytes()

base = 0xF000
start = 0xF562 - base

pixels = set()
i = start

while rom[i] != 0x60:
    block = rom[i:i+9]

    if block[0] != 0xA2 or block[1] != 0x00:
        raise Exception("bad block")
    if block[2] != 0xA0:
        raise Exception("bad block")
    if block[4] != 0xA9:
        raise Exception("bad block")
    if block[6:9] != bytes([0x20, 0x78, 0xF2]):
        raise Exception("bad block")

    y = block[3]
    x = block[5]

    pixels.add((x, y))
    i += 9

for y in range(1, 4):
    print("".join("#" if (x, y) in pixels else "." for x in range(31)))

font = {
    ("#.#", "#.#", ".#."): "V",
    (".#.", "##.", ".#."): "1",
    ("###", ".#.", ".#."): "T",
    (".##", "##.", ".##"): "{",
    ("###", "#.#", "###"): "O",
    ("...", "...", "###"): "_",
    ("##.", ".##", "##."): "}"
}

flag = ""

for start_x in range(0, 31, 4):
    glyph = tuple(
        "".join("#" if (x, y) in pixels else "." for x in range(start_x, start_x + 3))
        for y in range(1, 4)
    )
    flag += font[glyph]

print(flag)
```

Running it prints:

```text
#.#..#..###..##.###.....###.##.
#.#.##...#..##..#.#.....#.#..##
.#...#...#...##.###.###.###.##.
V1T{O_O}
```

## Flag

```text
V1T{O_O}
```
