---
title: 67xbet
date: 2026-07-06
tags:
- crypto
- LYKNCTF
---

- **Challenge:** 67xbet
- **Category:** Crypto
- **Flag:** `LYKNCTF{5348a970a3f64b1d9c2521b0da23416a}`

---

## My initial read / first impressions

The challenge page is a small betting themed site called **67xbet**. It shows five random-looking numbers and asks us to guess the sixth one:

```text
First 5 numbers (the 6th is hidden)
Guess the 6th number
```

Looking at the page source, the frontend is really simple. Pressing **Regenerate** calls:

```text
GET /api/random
```

and then submitting a guess calls:

```text
POST /api/validate
```

The important JavaScript is:

```javascript
body: JSON.stringify({
  numbers: currentNumbers,
  answer: answer,
  hash: currentHash
})
```

So the server gives us five numbers and a hash. Then we have to send the same five numbers, the hash, and our predicted sixth number back to the server.

That means the `hash` is probably just there so we cannot edit the first five numbers. The actual challenge is to recover whatever PRNG state generated them.

## False start: drand48

The page title says:

```text
Bookie's rigged random from Africa
```

and the visible page has a bunch of soccer match text, including **DR Congo**. My first thought was that **DR** might be hinting at `drand48`, which would make sense for a random-number challenge.

But the leaked numbers did not fit `drand48`. For example, one batch was:

```text
0.6137181383438468
0.9669686644312172
0.2785189365291869
0.768371397843814
0.2604852622927252
```

I tried reconstructing the 48-bit LCG state from the outputs, but even with a pretty wide rounding window it did not line up. So that clue was either a troll or just not the real PRNG.

## The real PRNG: V8 Math.random

The numbers looked much more like JavaScript `Math.random()` output. Modern V8 uses a xorshift128+ based PRNG internally, and `Math.random()` returns a double built from the high bits of one 64-bit state word.

For a generated state word `s0`, the returned number is basically:

```text
(s0 >> 12) / 2^52
```

That means every displayed random number leaks 52 bits from a 64-bit state word. Since the PRNG state is 128 bits total, five outputs are way more than enough information to recover the state.

There is one annoying V8 detail though: `Math.random()` uses a small cache of random values. It generates values internally, stores them, and then returns them in reverse order. So the five numbers shown by the page are usually reverse-chronological relative to the xorshift transitions.

So the plan became:

```text
/api/random
  -> get 5 leaked Math.random() values
  -> reverse them to match V8's internal generation order
  -> convert each float into its 52-bit mantissa leak
  -> solve the xorshift128+ state as linear equations over GF(2)
  -> step backwards once to get the next value the cache will pop
  -> submit that as the hidden 6th number
```

## Recovering the state

The xorshift transition is linear over bits, so this does not need brute force. I represented each of the 128 unknown state bits as a bit in a symbolic row, ran the xorshift transition symbolically, and added equations for the 52 leaked bits of each output.

The mantissa extraction is done by adding `1.0` to the random number and reading the IEEE-754 double bits:

```python
bits = struct.unpack("<Q", struct.pack("<d", x + 1.0))[0]
mantissa = bits & ((1 << 52) - 1)
```

Then each leaked mantissa bit becomes one equation in GF(2). After solving the linear system, I verified the recovered state by regenerating the leaked outputs exactly. Once that worked, I used the inverse xorshift transition once, because of the V8 cache reversal, and converted that previous state word into the next `Math.random()` value to submit.

For my successful run, the script got this batch:

```text
0.7487126656249559
0.9116571242095224
0.1522931383032915
0.7242501335984008
0.13998386089484827
```

and predicted:

```text
0.68763746819741245
```

Submitting that returned the flag immediately.

## Solution Script

Here is the final solve script I used. It gets a fresh batch from `/api/random`, recovers the V8 state, predicts the sixth value, and submits it to `/api/validate`.

```python
#!/usr/bin/env python3
import json
import struct
import sys
import time

import requests

BASE = "http://573a5020-cd14-4357-a78a-ca8be97a2c38.51.79.140.18.nip.io:8080"

MASK64 = (1 << 64) - 1
MANT_MASK = (1 << 52) - 1


def mantissa_from_float(x):
    x = float(x)
    bits = struct.unpack("<Q", struct.pack("<d", x + 1.0))[0]
    return bits & MANT_MASK


def to_double_from_state0(s0):
    return (s0 >> 12) / float(1 << 52)


def xs_step(s0, s1):
    x = s0
    y = s1
    s0 = y
    x ^= (x << 23) & MASK64
    x ^= x >> 17
    x ^= y
    x ^= y >> 26
    s1 = x & MASK64
    return s0, s1


def unxorshift_right(y, shift):
    x = 0
    for i in range(63, -1, -1):
        bit = (y >> i) & 1
        if i + shift < 64:
            bit ^= (x >> (i + shift)) & 1
        x |= bit << i
    return x & MASK64


def unxorshift_left(y, shift):
    x = 0
    for i in range(64):
        bit = (y >> i) & 1
        if i - shift >= 0:
            bit ^= (x >> (i - shift)) & 1
        x |= bit << i
    return x & MASK64


def xs_prev(s0, s1):
    old_s1 = s0
    v = s1 ^ old_s1 ^ (old_s1 >> 26)
    t = unxorshift_right(v, 17)
    old_s0 = unxorshift_left(t, 23)
    return old_s0 & MASK64, old_s1 & MASK64


def xor_word(a, b):
    return [x ^ y for x, y in zip(a, b)]


def shl_word(a, n):
    return [0] * n + a[:64 - n]


def shr_word(a, n):
    return a[n:] + [0] * n


def sym_step(s0, s1):
    x = s0[:]
    y = s1[:]

    t = xor_word(x, shl_word(x, 23))
    t = xor_word(t, shr_word(t, 17))
    t = xor_word(t, y)
    t = xor_word(t, shr_word(y, 26))

    return y, t


def build_rows(seq):
    # Variables:
    # bits 0..63   = state0
    # bits 64..127 = state1
    s0 = [1 << i for i in range(64)]
    s1 = [1 << (64 + i) for i in range(64)]

    rows = []
    rhs = []

    for val in seq:
        mant = mantissa_from_float(val)

        # V8 Math.random returns:
        # double = (state0 >> 12) / 2^52
        for j in range(52):
            rows.append(s0[12 + j])
            rhs.append((mant >> j) & 1)

        s0, s1 = sym_step(s0, s1)

    return rows, rhs


def solve_gf2(rows, rhs, nvars=128):
    mat = [r | (b << nvars) for r, b in zip(rows, rhs)]
    row = 0
    pivots = []

    for col in range(nvars):
        bit = 1 << col
        pivot = None

        for r in range(row, len(mat)):
            if mat[r] & bit:
                pivot = r
                break

        if pivot is None:
            continue

        mat[row], mat[pivot] = mat[pivot], mat[row]

        for r in range(len(mat)):
            if r != row and (mat[r] & bit):
                mat[r] ^= mat[row]

        pivots.append(col)
        row += 1

        if row == len(mat):
            break

    var_mask = (1 << nvars) - 1

    for r in mat:
        if (r & var_mask) == 0 and ((r >> nvars) & 1):
            return None

    sol = 0
    for r, col in enumerate(pivots):
        if (mat[r] >> nvars) & 1:
            sol |= 1 << col

    return sol


def word_from_solution(sol, offset):
    out = 0
    for i in range(64):
        if (sol >> (offset + i)) & 1:
            out |= 1 << i
    return out


def recover_state_for_chronological_sequence(seq):
    rows, rhs = build_rows(seq)
    sol = solve_gf2(rows, rhs)

    if sol is None:
        return None

    s0 = word_from_solution(sol, 0)
    s1 = word_from_solution(sol, 64)

    # Exact verification.
    a, b = s0, s1
    for val in seq:
        if (a >> 12) != mantissa_from_float(val):
            return None
        a, b = xs_step(a, b)

    return s0, s1


def candidate_answers(numbers):
    out = []

    # Real Node/V8 Math.random uses a 64-value cache and pops values in reverse.
    # So the 5 shown numbers are usually reverse-chronological.
    seq = list(reversed(numbers))
    st = recover_state_for_chronological_sequence(seq)

    if st is not None:
        first_s0, first_s1 = st
        prev_s0, _ = xs_prev(first_s0, first_s1)
        ans = to_double_from_state0(prev_s0)
        out.append(("v8-cache-reversed", ans))

    # Fallback in case the challenge manually uses the xorshift transition directly.
    seq = list(numbers)
    st = recover_state_for_chronological_sequence(seq)

    if st is not None:
        s0, s1 = st

        for _ in range(len(seq) - 1):
            s0, s1 = xs_step(s0, s1)

        next_s0, _ = xs_step(s0, s1)
        ans = to_double_from_state0(next_s0)
        out.append(("v8-direct", ans))

    return out


def main():
    sess = requests.Session()

    for attempt in range(1, 31):
        r = sess.get(BASE + "/api/random", timeout=10)
        r.raise_for_status()
        data = r.json()

        numbers = data["numbers"]
        h = data["hash"]

        print(f"\n[+] Attempt {attempt}")
        print("[+] Leaked numbers:")
        for i, n in enumerate(numbers, 1):
            print(f"    {i}. {n}")

        candidates = candidate_answers(numbers)

        if not candidates:
            print("[-] Could not fit this batch. Probably crossed V8's 64-number cache boundary; retrying...")
            time.sleep(0.15)
            continue

        for name, answer in candidates:
            answer_str = format(answer, ".17g")
            print(f"[+] Trying {name}: {answer_str}")

            payload = {
                "numbers": numbers,
                "answer": float(answer_str),
                "hash": h,
            }

            vr = sess.post(BASE + "/api/validate", json=payload, timeout=10)
            vr.raise_for_status()
            res = vr.json()

            print("[+] Response:", json.dumps(res))

            if "flag" in res:
                print("\n" + res["flag"])
                return

        time.sleep(0.15)

    print("[-] No flag after 30 attempts.")
    sys.exit(1)


if __name__ == "__main__":
    main()
```

Running it gave:

```text
[+] Attempt 1
[+] Leaked numbers:
    1. 0.7487126656249559
    2. 0.9116571242095224
    3. 0.1522931383032915
    4. 0.7242501335984008
    5. 0.13998386089484827
[+] Trying v8-cache-reversed: 0.68763746819741245
[+] Response: {"flag": "LYKNCTF{5348a970a3f64b1d9c2521b0da23416a}"}

LYKNCTF{5348a970a3f64b1d9c2521b0da23416a}
```

## Flag

```text
LYKNCTF{5348a970a3f64b1d9c2521b0da23416a}
```
