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

## My initial read / first impressions

We are given a Python script `chall.py` and a data file `keys.json`. The challenge implements a lattice-based encryption scheme. It looks very similar to standard Ring-LWE (Learning With Errors over Rings) or the Kyber Key Encapsulation Mechanism.

The parameters defined in the script are:
- Modulus $q = 3329$
- Polynomial degree $n = 512$
- Dimensions $k = 4$

The arithmetic operates in the polynomial ring $\mathbb{Z}_q[x] / (x^n + 1)$. This means we are dealing with polynomials of degree 511, where coefficients are integers modulo 3329, and multiplication wraps around with a sign change (negacyclic convolution).

The script defines an `encrypt` function and a `_vec_poly_mul` function. The encryption looks standard for LWE:
$$u = A^T r + e_1$$
$$v = t^T r + e_2 + \text{message\_encoding}$$

However, scrolling down to the actual execution flow in `chall.py`, I spotted the "Attack of the Clones":

```python
r = [_small_noise(n) for _ in range(k)]
e_1 = [_small_noise(n) for _ in range(k)]
e_2 = _small_noise(n)

u_1, v_1 = encrypt(A_1, t_1, m_b, r, e_1, e_2)
u_2, v_2 = encrypt(A_2, t_2, m_b, r, e_1, e_2)
```

The challenge generates a single set of ephemeral randomness—the secret vector $r$ and the error terms $e_1, e_2$—and uses them to encrypt the **same message** twice using two different public keys ($A_1$ and $A_2$).

In Lattice cryptography, the security relies entirely on the error terms $e$ making the system noisy and unsolveable. If we can eliminate that noise, the problem collapses into a simple system of linear equations.

## The Math

Let's write down the equations for the two ciphertexts we are given. Note that $A$ is a matrix of polynomials, and $r, e_1$ are vectors of polynomials.

1.  $u_1 = A_1^T \cdot r + e_1$
2.  $u_2 = A_2^T \cdot r + e_1$

Because the randomness was reused, the error vector $e_1$ is identical in both $u_1$ and $u_2$. This allows us to perform a simple subtraction to eliminate the error entirely:

$$u_1 - u_2 = (A_1^T \cdot r + e_1) - (A_2^T \cdot r + e_1)$$

Simplifying this, we get:

$$u_1 - u_2 = (A_1^T - A_2^T) r$$

Let $\Delta u = u_1 - u_2$ and $\Delta A = A_1 - A_2$. We are left with a noiseless linear equation:

$$\Delta u = \Delta A^T \cdot r$$

Here, $\Delta u$ is known (calculated from `keys.json`), $\Delta A$ is known, and $r$ is our unknown target. Since there is no error term, we can solve for $r$ using Gaussian elimination.

## Constructing the Solver

To solve this using a computer, we need to convert the polynomial arithmetic into linear algebra over the field $\mathbb{Z}_q$.

### From Polynomials to Matrices
Multiplication of two polynomials $a(x)$ and $b(x)$ in the ring $\mathbb{Z}_q[x] / (x^n + 1)$ can be represented as a matrix-vector multiplication. If we represent $b(x)$ as a vector of coefficients, multiplication by $a(x)$ is equivalent to multiplying by a "negacyclic" matrix formed from the coefficients of $a$.

For example, if $n=4$, multiplying by $a = [a_0, a_1, a_2, a_3]$ looks like this matrix:

$$
\begin{pmatrix}
a_0 & -a_3 & -a_2 & -a_1 \\
a_1 & a_0 & -a_3 & -a_2 \\
a_2 & a_1 & a_0 & -a_3 \\
a_3 & a_2 & a_1 & a_0
\end{pmatrix}
$$

### Building the System
Our system has dimensions $k=4$ and $n=512$.
- The vector $r$ has $k$ polynomials, so it has $4 \times 512 = 2048$ coefficients.
- The matrix $\Delta A^T$ is a $4 \times 4$ matrix of polynomials.

When we convert this to a scalar system over $\mathbb{Z}_q$, we get a massive $2048 \times 2048$ matrix. Each "cell" of the original $4 \times 4$ matrix becomes a $512 \times 512$ block representing the polynomial multiplication described above.

I used **SageMath** for this because it handles sparse matrices and modular arithmetic natively and efficiently.

### Decryption
Once we solve the linear system to recover $r$, we can decrypt the flag. We look at the second part of the ciphertext equation:

$$v_1 = t_1^T \cdot r + e_2 + \text{message}$$

We can calculate the "shared secret" part ourselves since we now know $r$:
$$v_{calc} = t_1^T \cdot r$$

Then we subtract it from the ciphertext:
$$\text{diff} = v_1 - v_{calc} = e_2 + \text{message}$$

The message is encoded such that a `0` bit is mapped to integer 0, and a `1` bit is mapped to integer $\lfloor q/2 \rfloor$ (around 1664). The error $e_2$ is small.
- If a coefficient in `diff` is close to 0 (or 3329), the bit is 0.
- If a coefficient is close to 1664, the bit is 1.

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