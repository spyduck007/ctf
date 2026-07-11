---
title: Waguri2
date: 2026-07-06
tags:
- rev
- LYKNCTF
---

- **Challenge:** Waguri2
- **Category:** Rev
- **Flag:** `LYKNCTF{K40RU_H4N4_W4_R1N_T0_S4KU}`

---

## My initial read / first impressions

The challenge description says:

```text
I found a strange program written in a flower-themed esolang. It keeps asking for input, but only one string makes it finish gracefully.

Can you translate the flowers back to something familiar?
```

The provided file is just a huge list of flower/anime-looking names like this:

```text
usami_shohei usami_shohei usami_shohei waguri_kaoruko waguri_kaoruko ...
```

So this immediately looked like an esolang substitution challenge. There are no normal strings, no binary to disassemble, and no obvious encoded flag sitting in the file. The main job is figuring out what each word means.

The phrase "translate the flowers back to something familiar" was the biggest hint. This was probably not a totally custom language. It was more likely a known esolang where the symbols had just been replaced with flower-themed tokens.

## Finding the esolang

The first thing I checked was how many unique tokens there were. The program only used seven different tokens:

```text
usami_shohei
waguri_kaoruko
yorita_ayato
tsumugi_rintaro
hoshina_subaru
natsusawa_saku
kaoru_hana
```

That is suspiciously close to Brainfuck. Brainfuck normally has eight instructions:

```text
> < + - [ ] , .
```

But this challenge is described as a program that asks for input and only needs to finish gracefully. It does not necessarily need to print anything. So having seven tokens makes sense if the program uses every Brainfuck instruction except output (`.`).

The next useful clue was that two tokens showed up in a way that looked exactly like matching loop delimiters. That gave the bracket pair:

```text
yorita_ayato   -> [
hoshina_subaru -> ]
```

Then `kaoru_hana` was the obvious input instruction, because it appeared at the points where the program needed to ask for/check another character:

```text
kaoru_hana -> ,
```

After that, the rest of the mapping fell into place by looking at the structure of the loops and long repeated runs:

```text
usami_shohei     -> >
natsusawa_saku   -> <
waguri_kaoruko   -> +
tsumugi_rintaro  -> -
yorita_ayato     -> [
hoshina_subaru   -> ]
kaoru_hana       -> ,
```

So the flower language was just Brainfuck wearing a very cute disguise.

## Translating it back

I used a small translator to convert the token stream back into Brainfuck:

```python
#!/usr/bin/env python3

mapping = {
    "usami_shohei": ">",
    "natsusawa_saku": "<",
    "waguri_kaoruko": "+",
    "tsumugi_rintaro": "-",
    "yorita_ayato": "[",
    "hoshina_subaru": "]",
    "kaoru_hana": ",",
}

with open("output.txt", "r") as f:
    tokens = f.read().split()

bf = "".join(mapping[t] for t in tokens)

print(bf)
print("input instructions:", bf.count(","))
```

The translated program had 34 input instructions, so I knew the accepted string should be 34 characters long. That length also lines up perfectly with a normal LYKNCTF flag:

```text
LYKNCTF{..........................}
```

## Recovering the input

At this point there were two options:

```text
1. Manually decompile the Brainfuck validator.
2. Write a tiny interpreter and brute-force the accepted input one character at a time.
```

I went with the second option, because the program behaves like a checker. If the current character is right, execution keeps moving to the next input/check. If it is wrong, it gets stuck in a loop instead of finishing cleanly.

So I wrote an interpreter with a step limit and tried printable characters for each position. Whenever a candidate allowed the program to get farther, I kept it and moved on.

The important idea was basically:

```python
charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{}_@-!$0123456789"
flag = ""

for i in range(34):
    for c in charset:
        candidate = flag + c
        result = run_brainfuck(program, candidate, step_limit=2_000_000)

        if result.got_farther_than_the_other_candidates:
            flag += c
            print(flag)
            break
```

This recovered the input character by character. The prefix started with:

```text
L
LY
LYK
LYKN
LYKNC
LYKNCT
LYKNCTF
```

So it was definitely the flag and not some random passphrase.

## The accepted string

The final input that makes the program finish gracefully is:

```text
LYKNCTF{K40RU_H4N4_W4_R1N_T0_S4KU}
```

This also matches the theme of the challenge. The token names are all references around **Kaoru Hana wa Rin to Saku**, and the flag itself is a leetspeak version of that phrase.

## Flag

```text
LYKNCTF{K40RU_H4N4_W4_R1N_T0_S4KU}
```
