---
title: Attack of the Clones
date: 2025-11-28
tags:
  - crypto
  - LakeCTF-Quals-2025
---

**Challenge:** Attack of the Clones  
**Category:** Crypto  
**Flag:** `EPFL{2oo000_un1t5_r34dy_w1th_4_m1ll10n_m0r3_w3ll_0n_th3_w4y_i6o}`

---

## My initial read / first impressions

We are given a Python script `chall.py` and a data file `keys.json`. The challenge implements a specific type of cryptography based on lattices. If you are familiar with Ring-LWE (Learning With Errors) or the Kyber algorithm used in post-quantum cryptography, this structure looks very familiar.

The script defines a few specific parameters:

- **Modulus (q):** 3329 (all numbers are kept within this range).
- **Dimension (n):** 512 (we are working with polynomials that have 512 coefficients).
- **k:** 4 (the matrices are 4x4 grids of these polynomials).

The math operates in a "Polynomial Ring". In simple terms, this means we add and multiply polynomials. If the coefficients get too big, we take the remainder modulo 3329. If the polynomial gets too long (degree 512 or higher), we wrap it around using a rule where `x^512` becomes `-1`.

The encryption function looks standard for this type of cryptography. It takes a public matrix `A`, a public vector `t`, and a message. It generates a secret vector `r` and two error vectors, `e1` and `e2`.

The equations for the ciphertext parts `u` and `v` are essentially:

1. `u = A * r + e1`
2. `v = t * r + e2 + message`

The security of this system relies entirely on `e1` and `e2`. These are random "noise" that make it mathematically impossible to figure out `r` or the `message` just by looking at the public keys and ciphertexts.

## The Vulnerability

I looked at the specific section of the code that runs the encryption:

```python
r = [_small_noise(n) for _ in range(k)]
e_1 = [_small_noise(n) for _ in range(k)]
e_2 = _small_noise(n)

u_1, v_1 = encrypt(A_1, t_1, m_b, r, e_1, e_2)
u_2, v_2 = encrypt(A_2, t_2, m_b, r, e_1, e_2)
```

This is where the "Attack of the Clones" happens. The challenger generates the randomness **once**. Specifically, the secret vector `r` and the error vector `e1` are generated a single time.

Then, the script encrypts the **same message** twice.

1. First, using Public Key 1 (`A1`, `t1`).
2. Second, using Public Key 2 (`A2`, `t2`).

Because the randomness was reused, we can break the encryption. The vulnerability lies in the fact that the error term `e1` is identical in both encrypted outputs.

## The Logic

Let's look at the equations for the first part of the ciphertext (`u`) for both encryptions:

1. `u1 = A1 * r + e1`
2. `u2 = A2 * r + e1`

In algebra, if you have two equations with the same unknown value added to them, you can subtract the equations to get rid of that value. Here, we can subtract the second equation from the first to completely eliminate the error `e1`.

`u1 - u2 = (A1 * r + e1) - (A2 * r + e1)`

The `e1` cancels out, leaving us with:

`u1 - u2 = (A1 - A2) * r`

We know `u1` and `u2` from the file provided. We also know the public keys `A1` and `A2`. We can calculate the difference between the ciphertexts (let's call it `diff_u`) and the difference between the keys (let's call it `diff_A`).

We are left with a clean linear equation with no noise:
`diff_u = diff_A * r`

This is just a system of linear equations. We can solve this to find `r` directly.

## Constructing the Solver

To solve this using a computer, we need to translate the "polynomial multiplication" used in the encryption into standard linear algebra (matrices and vectors of numbers).

### From Polynomials to Matrices

When you multiply two polynomials in this specific ring, it is equivalent to multiplying a vector by a special kind of matrix called a "negacyclic matrix".

If we treat our unknown `r` as a long list of numbers, multiplying it by a polynomial coefficient involves shifting the list.

- Multiplying by a constant is just standard multiplication.
- Multiplying by `x` shifts every number to the right by one spot.
- The number that falls off the end wraps around to the front, but its sign is flipped (multiplied by -1).

### Building the System

We have `k=4` polynomials, each with `n=512` coefficients.

- The vector `r` contains 4 polynomials, so it has `4 * 512 = 2048` total variables.
- The matrix we built (`diff_A`) is a 4x4 grid of polynomials.

When we convert this to a standard system of numbers, we get a massive grid of size 2048x2048. I used **SageMath** to build this matrix because it has excellent built-in tools for handling sparse matrices (matrices mostly filled with zeros) and doing math with a modulus.

### Decryption

Once we solve the system, we have the secret vector `r`. Now we can look at the second part of the ciphertext to get the flag.

The equation for the second part is:
`v1 = t1 * r + e2 + message`

Since we know the public key `t1` and we just recovered `r`, we can calculate the "shared secret" part ourselves:
`shared_secret = t1 * r`

Now we subtract that from the ciphertext:
`remainder = v1 - shared_secret`

Mathematically, `remainder` is equal to `e2 + message`.

- `e2` is very small "noise".
- The `message` is encoded bits. A binary `0` is encoded as the number 0. A binary `1` is encoded as a number roughly half the size of the modulus (approx. 1664).

So, to decrypt, we just look at each number in the remainder:

- If the number is close to 0 (or close to 3329), the bit is **0**.
- If the number is close to 1664, the bit is **1**.

## Solution Script

Here is the final SageMath script. It loads the keys, constructs the large linear system by computing the difference between the two instances, solves for the reused randomness `r`, and decrypts the flag.

```python
import json
from sage.all import GF, vector, matrix, PolynomialRing

with open("keys.json", "r") as f:
    data = json.load(f)

q, n, k = 3329, 512, 4

A1 = data["A_1"]
A2 = data["A_2"]
u1 = data["u_1"]
u2 = data["u_2"]
t1 = data["t_1"]
v1 = data["v_1"]

D = [[[ (A1[l][j][i] - A2[l][j][i]) % q for i in range(n)] for j in range(k)] for l in range(k)]
u_diff = [[(u1[i][x] - u2[i][x]) % q for x in range(n)] for i in range(k)]

y_list = []
for row in u_diff:
    y_list.extend(row)
y = vector(GF(q), y_list)

M = matrix(GF(q), k*n, k*n, sparse=True)
for i in range(k):
    for j in range(k):
        coeffs = [D[l][j][i] for l in range(k)]
        row_offset, col_offset = i * n, j * n
        for l, c in enumerate(coeffs):
            if c == 0: continue
            for idx in range(n - l):
                M[row_offset + idx + l, col_offset + idx] += c
            for idx in range(n - l, n):
                target_row = idx + l - n
                M[row_offset + target_row, col_offset + idx] -= c

r_vec = M.solve_right(y)

r = [list(r_vec[j*n : (j+1)*n]) for j in range(k)]

R = PolynomialRing(GF(q), 'x')
x = R.gen()
modulus = x^n + 1

def poly_mul_mod(p1_list, p2_list):
    return (R(p1_list) * R(p2_list) % modulus).list()

v_calc = [0] * n
for idx in range(k):
    prod_ints = [int(x) for x in poly_mul_mod(t1[idx], r[idx])]
    for i in range(n):
        if i < len(prod_ints):
            v_calc[i] = (v_calc[i] + prod_ints[i]) % q

diff = [(v1[i] - v_calc[i]) % q for i in range(n)]

bits = []
center = q // 2
for val in diff:
    val = int(val)
    dist_to_center = abs(val - center)
    dist_to_zero = min(val, q - val)
    bits.append(1 if dist_to_center < dist_to_zero else 0)

flag_chars = [chr(int("".join(str(b) for b in bits[i:i+8]), 2)) for i in range(0, len(bits), 8) if len(bits[i:i+8]) == 8]
flag = "".join(flag_chars)

print(flag)
```

Running the script recovers the flag successfully.
