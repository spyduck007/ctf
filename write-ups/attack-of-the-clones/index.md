---
layout: post
title: "Attack of the Clones"
categories: [crypto, LakeCTF-Quals-2025]
date: 2025-11-28 13:04:55 -0500
writeup: true
permalink: /write-ups/pdfbill/
order: 1
---

**Challenge:** Attack of the Clones  
**Category:** Crypto  
**Flag:** ``EPFL{2oo000_un1t5_r34dy_w1th_4_m1ll10n_m0r3_w3ll_0n_th3_w4y_i6o}``

---

## Initial Analysis

We are provided with a Python script `chall.py` and a `keys.json` file containing large matrices and vectors. Reading through `chall.py`, it implements a lattice-based encryption scheme very similar to Ring-LWE (Learning With Errors over Rings) or Kyber.

The parameters are defined as:
- `q = 3329`
- `n = 512`
- `k = 4`
- Polynomial ring `R_q = Z_q[x] / (x^n + 1)`

The encryption function takes a public matrix `A`, a public vector `t`, a message `m`, and randomness terms `r`, `e1`, `e2`.

`u = A^T * r + e1`
`v = t^T * r + e2 + floor(q/2) * m`

However, looking at the "Encryption" section of the code, a critical vulnerability appears immediately:

```python
r = [_small_noise(n) for _ in range(k)]
e_1 = [_small_noise(n) for _ in range(k)]
e_2 = _small_noise(n)

u_1, v_1 = encrypt(A_1, t_1, m_b, r, e_1, e_2)
u_2, v_2 = encrypt(A_2, t_2, m_b, r, e_1, e_2)
```

The challenger generates **one set** of randomness (`r`, `e1`, `e2`) and uses it to encrypt the **same message** (`m_b`) twice, but with two different public keys (`A1`, `t1`) and (`A2`, `t2`). This is a classic "nonce reuse" or "randomness reuse" attack scenario, hence the name "Attack of the Clones".

## The Vulnerability

Let's look at the structure of the ciphertexts `u1` and `u2`:

1.  `u1 = A1^T * r + e1`
2.  `u2 = A2^T * r + e1`

Since `e1` is identical in both equations, we can subtract the second equation from the first to eliminate the error term entirely:

`u1 - u2 = (A1^T * r + e1) - (A2^T * r + e1)`
`u1 - u2 = (A1^T - A2^T) * r`

Let `delta_u = u1 - u2` and `delta_A = A1 - A2`. We now have:

`delta_u = delta_A^T * r`

This is a system of linear equations. `A1` and `A2` are known public matrices (provided in `keys.json`), and `u1`, `u2` are known ciphertexts. The only unknown is `r`.

Usually, in Lattice cryptography, finding `r` is hard because of the error term `e1` (the Learning With Errors problem). By eliminating `e1`, we reduce the problem to simple linear algebra over the finite field `Z_q`.

## Solving for r

The equation `delta_u = delta_A^T * r` involves polynomial multiplication in the ring `R_q`. To solve this using standard linear algebra solvers (like Gaussian elimination), we can represent the polynomial multiplication as a matrix-vector multiplication over `Z_q`.

Since `n=512` and `k=4`, the vectors `u` and `r` effectively contain `4 * 512 = 2048` coefficients. We can construct a 2048x2048 matrix `M` where each block represents the negacyclic convolution (multiplication by `x^n = -1`) corresponding to the polynomials in `delta_A`.

Once we solve for `r`, we can decrypt the message. The second part of the ciphertext is:

`v1 = t1^T * r + e2 + encoded_message`

We can compute `v_calc = t1^T * r`. Then:

`v1 - v_calc = e2 + encoded_message`

Since `e2` consists of "small noise", the value `v1 - v_calc` will be close to the scaled message bits. Specifically:
- If the bit is 0, the value is close to 0 (or `q`).
- If the bit is 1, the value is close to `q/2` (approx 1664).

## Implementation

I used **SageMath** to handle the linear algebra and polynomial arithmetic.

1.  **Data Loading**: Parse `keys.json`.
2.  **Difference Calculation**: Compute `delta_A = A1 - A2` and `delta_u = u1 - u2`.
3.  **Matrix Construction**: Build the large sparse matrix `M` representing the linear transformation over `Z_q`. The `encrypt` function uses `zip` on transposed matrices, so we map the coefficients of `delta_A` carefully into the band matrix structure.
4.  **Solving**: Use `M.solve_right(y)` to find `r`.
5.  **Decryption**: Recompute the shared secret, subtract it from `v1`, and decode the bits based on their proximity to `q/2`.

### Solution Script

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