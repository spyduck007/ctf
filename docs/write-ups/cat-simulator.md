---
title: Cat Simulator
date: 2026-07-11
tags:
- rev
- BroncoCTF-2026
---

- **Challenge:** Cat Simulator
- **Category:** Rev
- **Flag:** `bronco{fluffy_baby}`

---

## My initial read / first impressions

The challenge description says:

```text
Make the purrfect choices over 5 days to win your owner's heart... and maybe something more? Meow carefully.
```

We are given a Linux binary called `cat-sim-linux`. Running it gives a cute little 5-day cat simulator where each day you pick an action. The obvious idea is to just play the game normally and try to maximize whatever affection/score system it has.

But since this is a rev challenge, I assumed the game probably had a very specific hidden route instead of just "pick the nicest sounding option every time."

## Basic reversing

I started by checking the binary normally:

```bash
file cat-sim-linux
strings cat-sim-linux
```

The strings showed normal game text, but not the flag directly. So the next step was opening the binary in a decompiler and looking for the final check around the ending logic.

The important part was that the game keeps track of more than just the final score. It also tracks how many times each type of action was picked, whether any invalid choices were made, and the total length of the messages typed during the `talk` action.

So the win condition is not just "get the highest score." The game wants a very specific playthrough.

## The hidden final check

The final flag branch checks these conditions:

```text
invalid_choices == 0
talk_count == 3
scratch_count == 1
eat_count == 1
score == 45
total_talk_message_length == 32
affection > 0
```

That means across the 5 days, the correct actions are:

```text
3 talks
1 scratch
1 eat
```

The order does not really matter for the counts, but the total length of the three talk messages has to be exactly 32 characters. The actual text does not matter, only the length.

Since the program trims the newline after each message, I used talk messages of lengths:

```text
11 + 11 + 10 = 32
```

## Solving it

This input satisfies all the checks:

```bash
printf '\n1\naaaaaaaaaaa\n1\nbbbbbbbbbbb\n1\ncccccccccc\n2\n3\n' ./cat-sim-linux
```

The first blank line is just for the initial prompt before the 5 days start. Then the choices are:

```text
Day 1: talk, say 11 characters
Day 2: talk, say 11 characters
Day 3: talk, say 10 characters
Day 4: scratch
Day 5: eat
```

Running that gives the special ending:

```text
=== Day 5 Finale ===
Owner: awwww it said "bronco{fluffy_baby}"

Final score: 45
Have an ameowsing day!
```

## Why this works

The main trick is that the visible simulator is kind of a decoy. If you only think about it like a normal game, you might try to maximize affection or pick whatever seems cutest. But the flag branch is checking exact internal counters.

So the solve is:

```text
reverse final ending logic
    -> find exact counter checks
    -> choose 3 talks, 1 scratch, 1 eat
    -> make the talk messages total 32 characters
    -> trigger the hidden ending
    -> get the flag
```

## Flag

```text
bronco{fluffy_baby}
```
