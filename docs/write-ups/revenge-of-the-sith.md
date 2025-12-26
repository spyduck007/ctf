---
title: Revenge of the Sith
date: 2025-11-28
tags:
  - crypto
  - LakeCTF-Quals-2025
---

**Challenge:** Revenge of the Sith  
**Category:** Crypto  
**Flag:** `EPFL{N07_0N1Y_7H3_m3n_BU7_7h3_w0M3N_4ND_CHILDR3N_7o0_T50nanWvW1}`

---

## My initial read / first impressions

We are provided with `chall.py` and `keys.json`. The Python script implements a cryptographic system that looks exactly like modern post-quantum algorithms (specifically Module-LWE, the basis for Kyber). It generates keys, encrypts a secret flag, and saves the results to a file.

However, the first thing that caught my eye was the configuration at the top of the script:

```python
# Parameters
q = 251
n = 16
k = 2
```

In real-world cryptography, the number `n` (the number of coefficients in our equations) is usually 256 or larger, and `q` (the modulus) is usually in the thousands.

Here, `n` is only 16. This is incredibly small.

The encryption works by hiding a secret key inside a mathematical equation and adding some random "noise" so you can't solve it with standard algebra. Usually, the sheer size of the numbers makes it impossible to find the secret despite the noise. But with `n=16`, the "search space" is tiny. This suggests we can simply force the math to reveal the secret using lattice attacks.

## The Vulnerability

The vulnerability here is **Weak Parameters**.

The encryption relies on the "Learning With Errors" (LWE) problem. The idea is that if I give you a matrix `A` and a result `t`, where `t = A * secret + noise`, you can't find the `secret` because the `noise` messes up the calculation.

However, this problem is geometric. You can imagine the `secret` as a specific point in a multi-dimensional grid (a lattice). The `noise` moves the point slightly off the grid intersection. If the dimensions are high enough (like 256 dimensions), finding the original grid point is impossible.

But since we only have 16 dimensions (technically 32 total variables), the grid is small enough that we can use a special algorithm called **LLL** (Lenstra–Lenstra–Lovász). LLL is designed to find the "shortest vector" in a lattice. Since our secret key and the noise are made of very small numbers (mostly -1, 0, and 1), the vector containing our secret key is geometrically the "shortest" thing in the entire grid.

## The Logic

### 1. The Setup

We need to translate the challenge's polynomial math into a linear grid that the LLL algorithm can understand.

The challenge uses polynomials (lists of numbers), but LLL works on matrices (grids of numbers). We can convert the polynomials into matrices by following a simple rule: when you multiply by a polynomial, it's like shifting the numbers in a list. If a number falls off the end, it wraps around to the beginning with a flipped sign.

### 2. Building the Lattice

We construct a large matrix (the lattice basis) that represents the equation `A * secret - t = -noise`.

The matrix includes:

1.  The public key matrix `A`.
2.  The modulus `q` (so the math wraps around 251 correctly).
3.  The public result vector `t`.

We are essentially asking the computer: "Find me a set of small numbers that, when multiplied by `A`, gets extremely close to `t`."

### 3. Running LLL

We feed this matrix into the LLL algorithm. It will return a new, "reduced" matrix containing the shortest vectors it could find.

One of these short vectors will essentially look like this: `[secret_key, error, 1]`.

Because the challenge uses such small parameters, LLL will find this almost instantly. We can just read the secret key directly out of the first row of the result.

### 4. Decrypting

Once we have the secret key, the cryptography is broken. We take the encrypted messages provided in `keys.json` and reverse the process:

1.  Calculate `shared_secret = public_ciphertext * secret_key`.
2.  Subtract this from the second part of the ciphertext.
3.  The result will be the message plus a tiny bit of noise. We round the numbers to the nearest valid value (0 or 1) to get the flag.

## Solution Script

I used **SageMath** to solve this. Sage is perfect for CTFs like this because it handles the lattice reduction (LLL) and the polynomial math automatically.

```python
import json

with open("keys.json", "r") as f:
    data = json.load(f)

q = 251
n = 16
A_raw = data["A"]
t_raw = data["t"]
u_raw = data["u"]
v_raw = data["v"]

def make_cyclic_matrix(poly_list):
    mat = []
    current = poly_list[:]
    for _ in range(n):
        mat.append(current[:])
        last = current.pop()
        current.insert(0, (-last) % q)
    return matrix(ZZ, mat).transpose()

M00 = make_cyclic_matrix(A_raw[0][0])
M01 = make_cyclic_matrix(A_raw[0][1])
M10 = make_cyclic_matrix(A_raw[1][0])
M11 = make_cyclic_matrix(A_raw[1][1])
A_mat = block_matrix([[M00, M01], [M10, M11]])

t_vec = vector(ZZ, t_raw[0] + t_raw[1])

dim = 32
identity = identity_matrix(ZZ, dim)
zero_mat = matrix(ZZ, dim, dim, 0)

lattice = block_matrix([
    [identity,                A_mat.transpose(),       matrix(ZZ, dim, 1, 0)],
    [zero_mat,                identity * q,            matrix(ZZ, dim, 1, 0)],
    [matrix(ZZ, 1, dim, 0),   matrix(ZZ, -t_vec),      matrix(ZZ, 1, 1, 1)]
])

reduced_lattice = lattice.LLL()

secret_key = None

for row in reduced_lattice:
    if row[-1] == 1:
        candidate = row[:dim]
        if all(abs(x) <= 1 for x in candidate):
            secret_key = candidate
            break
    elif row[-1] == -1:
        candidate = -row[:dim]
        if all(abs(x) <= 1 for x in candidate):
            secret_key = candidate
            break

s_poly = [list(secret_key[:16]), list(secret_key[16:])]

def poly_mul_mod(p1, p2):
    res = [0] * (2 * n)
    for i in range(n):
        for j in range(n):
            res[i+j] += p1[i] * p2[j]
    final = [0] * n
    for i in range(len(res)):
        if i < n:
            final[i] = (final[i] + res[i])
        else:
            final[i-n] = (final[i-n] - res[i])
    return [x % q for x in final]

decrypted_bits = []

for u, v in zip(u_raw, v_raw):
    dot_product = [0]*n
    for i in range(2):
        term = poly_mul_mod(s_poly[i], u[i])
        dot_product = [(x + y) % q for x, y in zip(dot_product, term)]
    diff = [(x - y) % q for x, y in zip(v, dot_product)]
    for val in diff:
        dist_to_1 = abs(val - 125)
        dist_to_0 = min(val, 251 - val)
        decrypted_bits.append(1 if dist_to_1 < dist_to_0 else 0)

chars = []
for i in range(0, len(decrypted_bits), 8):
    byte_bits = decrypted_bits[i:i+8]
    if len(byte_bits) < 8:
        break
    chars.append(chr(int("".join(map(str, byte_bits)), 2)))

print("Flag:", "".join(chars))
```

Running this script breaks the small lattice instantly and prints out the flag.
