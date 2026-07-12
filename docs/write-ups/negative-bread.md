---
title: Negative Bread
date: 2026-07-11
tags:
- rev
- BroncoCTF-2026
---

- **Challenge:** Negative Bread
- **Category:** Rev
- **Flag:** `bronco{th3_b4nk_0w3s_m3_m0n3y}`

---

## My initial read / first impressions

The challenge description says:

```text
Your account starts at $100. The flag costs $1,000,000. Deposits are capped. Withdrawals can't go below zero.

No strings attached.

We don't even need to guard the vault. This bank is impenetrable!
```

We are given a binary called `bank`. Running it gives a small banking menu where the account starts with only `$100`, while the flag costs `$1,000,000`.

The obvious routes are blocked:

```text
deposits are capped
withdrawals cannot make the balance negative
the flag is way too expensive normally
```

So this already sounds like the bug is not going to be normal money logic like "deposit a huge number." The line `No strings attached` also feels like a hint that this is not a string bug. Since this is a rev challenge with bank/math logic, I started looking for integer weirdness.

## Looking through the menu logic

The important options are the dispute/refund option and the buy-flag option.

The balance is stored as a signed 32-bit integer. That is already important because the range is roughly:

```text
-2147483648 to 2147483647
```

The program tries to prevent normal abuse. Deposits have a cap, and withdrawals check that the balance will not go below zero.

However, the dispute option has a different kind of check. It tries to make sure the disputed amount is not too large by checking the absolute value of the input.

That is where the bug is.

## The `INT_MIN` problem

For a normal negative number, `abs()` works how you would expect:

```text
abs(-100) = 100
```

But for a 32-bit signed integer, the smallest possible value is:

```text
-2147483648
```

The positive version would be:

```text
2147483648
```

That value does not fit inside a signed 32-bit integer, because the maximum is only `2147483647`.

So `abs(-2147483648)` cannot be represented correctly. In this binary, that means the value stays negative and slips past the refund limit check.

I used the dispute option with:

```text
-2147483648
```

Instead of giving me a normal refund, the program applies that negative value directly to the balance:

```text
starting balance: 100
refund:          -2147483648
new balance:     -2147483548
```

At first that looks worse, because now the account has a massive negative balance. But the flag check has a second bug.

## The unsigned comparison

The flag costs `$1,000,000`, so the program checks whether the balance is high enough.

The problem is that the buy-flag check compares the balance as an unsigned integer.

So when the signed balance is:

```text
-2147483548
```

it gets interpreted as a huge unsigned value instead of a negative number.

That means the program thinks we have way more than `$1,000,000`, even though the signed balance is negative. Somehow being extremely broke makes the bank think we are rich. Incredible financial system.

## Solving it

The final input sequence is very short:

```bash
printf '3\n-2147483648\n5\n' | ./bank
```

This does:

```text
3              -> dispute/refund option
-2147483648    -> trigger the INT_MIN abs bug
5              -> buy the flag
```

Running it gives:

```text
[+] Dispute processed. Refund of $-2147483648 applied.
    New balance: $-2147483548

[!] TRANSACTION APPROVED
bronco{th3_b4nk_0w3s_m3_m0n3y}
```

## Why this works

The challenge is a signed integer edge case chained with a signed/unsigned comparison bug.

The full chain is:

```text
account starts at 100
    -> use dispute option
    -> enter -2147483648
    -> abs(INT_MIN) fails because +2147483648 cannot fit in int32
    -> balance becomes a huge negative signed number
    -> buy-flag check treats balance as unsigned
    -> negative balance becomes a huge positive value
    -> flag purchase succeeds
```

So the vault was not guarded because the program trusted its integer checks a little too much.

## Flag

```text
bronco{th3_b4nk_0w3s_m3_m0n3y}
```
