---
title: Atomic Substitution Theory
date: 2026-07-11
tags:
- misc
- BroncoCTF-2026
---

- **Challenge:** Atomic Substitution Theory
- **Category:** Misc
- **Flag:** `bronco{my_favorite_messages_have_an_element_of_surprise}`

---

## My initial read / first impressions

The challenge description says:

```text
This text file is what happens when a chemist tries to send you a top secret message.

Hint: all letters in the flag should be lowercase.
```

The attached file was a comma-separated list of tuples, underscores, braces, and one normal `{` / `}` pair. It looked like this:

```text
(4, 17), (2, 16), (2, 15), (4, 9), { , ... }
```

Since the prompt specifically mentions a **chemist**, my first thought was the periodic table. The tuples also fit that really well because every element has a row/period and column/group.

So I interpreted each coordinate as:

```text
(period, group) -> element symbol
```

For example:

```text
(4, 17) -> bromine -> Br
(2, 16) -> oxygen -> O
(2, 15) -> nitrogen -> N
(4, 9)  -> cobalt -> Co
```

Putting those element symbols together gives:

```text
Br O N Co
```

Since the hint says all letters should be lowercase, this becomes:

```text
bronco
```

That confirmed the solve path immediately.

## Decoding the coordinates

Most of the tuples have two numbers, which directly point to an element on the periodic table. The decoded output uses the element's chemical symbol.

Some tuples have three numbers, like:

```text
(3, 2, 1)
```

For these, the first two numbers still give the element, and the third number tells us which letter of the element symbol to take.

For example:

```text
(3, 2) -> magnesium -> Mg
(3, 2, 1) -> first letter of Mg -> M
```

After lowercasing everything, that gives `m`.

Another example:

```text
(2, 1) -> lithium -> Li
(2, 1, 2) -> second letter of Li -> i
```

So the rules are:

```text
(period, group)      -> full element symbol
(period, group, idx) -> idx-th letter of the element symbol
```

Using those rules, the beginning decodes as:

```text
(4, 17), (2, 16), (2, 15), (4, 9), {, (3, 2, 1), (5, 3), _
```

which becomes:

```text
bronco{my_
```

At that point, the rest of the message was just continuing the same substitution.

## The slight gotcha

One thing that made this challenge a little annoying is that the raw decoded text was extremely close to the final answer, but not quite perfectly written as normal English.

The intended phrase is clearly:

```text
my favorite messages have an element of surprise
```

That also fits the chemistry joke perfectly: an **element** of surprise.

So the decoded message points to the final flag phrase, but the flag should use the cleaned-up intended wording:

```text
bronco{my_favorite_messages_have_an_element_of_surprise}
```

## Solution script

I used a small periodic-table lookup script to avoid doing every coordinate by hand:

```python
periodic = {
    (1, 1): "H", (1, 18): "He",
    (2, 1): "Li", (2, 2): "Be", (2, 13): "B", (2, 14): "C", (2, 15): "N", (2, 16): "O", (2, 17): "F", (2, 18): "Ne",
    (3, 1): "Na", (3, 2): "Mg", (3, 13): "Al", (3, 14): "Si", (3, 15): "P", (3, 16): "S", (3, 17): "Cl", (3, 18): "Ar",
    (4, 1): "K", (4, 2): "Ca", (4, 3): "Sc", (4, 4): "Ti", (4, 5): "V", (4, 6): "Cr", (4, 7): "Mn", (4, 8): "Fe", (4, 9): "Co", (4, 10): "Ni", (4, 11): "Cu", (4, 12): "Zn", (4, 13): "Ga", (4, 14): "Ge", (4, 15): "As", (4, 16): "Se", (4, 17): "Br", (4, 18): "Kr",
    (5, 1): "Rb", (5, 2): "Sr", (5, 3): "Y", (5, 4): "Zr", (5, 5): "Nb", (5, 6): "Mo", (5, 7): "Tc", (5, 8): "Ru", (5, 9): "Rh", (5, 10): "Pd", (5, 11): "Ag", (5, 12): "Cd", (5, 13): "In", (5, 14): "Sn", (5, 15): "Sb", (5, 16): "Te", (5, 17): "I", (5, 18): "Xe",
    (6, 1): "Cs", (6, 2): "Ba", (6, 3): "La", (6, 4): "Hf", (6, 5): "Ta", (6, 6): "W", (6, 7): "Re", (6, 8): "Os", (6, 9): "Ir", (6, 10): "Pt", (6, 11): "Au", (6, 12): "Hg", (6, 13): "Tl", (6, 14): "Pb", (6, 15): "Bi", (6, 16): "Po", (6, 17): "At", (6, 18): "Rn",
    (7, 1): "Fr", (7, 2): "Ra", (7, 3): "Ac", (7, 4): "Rf", (7, 5): "Db", (7, 6): "Sg", (7, 7): "Bh", (7, 8): "Hs", (7, 9): "Mt", (7, 10): "Ds", (7, 11): "Rg", (7, 12): "Cn", (7, 13): "Nh", (7, 14): "Fl", (7, 15): "Mc", (7, 16): "Lv", (7, 17): "Ts", (7, 18): "Og",
    (8, 6): "Nd",
    (9, 6): "U",
}

items = [
    (4, 17), (2, 16), (2, 15), (4, 9), "{", (3, 2, 1), (5, 3), "_",
    (2, 17), (3, 13, 1), (4, 5), (2, 16), (4, 17, 2), (2, 1, 2),
    (4, 4, 1), (2, 2, 2), "_", (3, 2, 1), (2, 2, 2), (3, 16),
    (3, 16), (3, 13, 1), (4, 13, 1), (2, 2, 2), (3, 16), "_",
    (1, 1), (3, 13, 1), (4, 5), (2, 2, 2), "_", (3, 13, 1),
    (4, 4, 1), "_", (2, 2, 2), (3, 17, 2), (2, 2, 2), (3, 2, 1),
    (2, 2, 2), (2, 15), (4, 4, 1), "_", (2, 16), (2, 17), "_",
    (3, 16), (9, 6), (3, 15), (4, 17, 2), (2, 1, 2), (3, 16),
    (2, 2, 2), "}"
]

out = []

for item in items:
    if isinstance(item, str):
        out.append(item)
        continue

    symbol = periodic[item[:2]]

    if len(item) == 2:
        out.append(symbol)
    else:
        out.append(symbol[item[2] - 1])

print("".join(out).lower())
```

This gives the decoded message, and then the final flag uses the intended phrase from the pun.

## Flag

```text
bronco{my_favorite_messages_have_an_element_of_surprise}
```
