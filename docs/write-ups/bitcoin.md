---
title: Bitcoin
date: 2026-01-23
tags:
  - crypto
  - 0xL4ugh-CTF-v5
---

**Challenge:** Bitcoin  
**Category:** Crypto  
**Flag:** `0xL4ugh{B1tc0in_Squiggl3_d3m0_By_Zwique_1af5f2582942ff7d}`

---

## My initial read / first impressions

We are provided with a `netcat` connection to a service titled "Curve Oracle Service v2.0". The challenge name "Bitcoin" strongly implies the use of the **secp256k1** elliptic curve, which has the equation `y^2 = x^3 + 7`.

Upon connecting, the service describes its operation:
1. It holds a secret key `d`.
2. It asks for two ElGamal components, `C1` and `C2`.
3. It returns a value `S` calculated as `S = C2 - (d * C1)`.

The service runs this query 5 times in "Phase 1". If we survive that, there is a "Phase 2".

My immediate suspicion was an **Invalid Curve Attack**. In ECC implementation, the point addition formulas often do not use the `b` parameter of the curve equation (`y^2 = x^3 + ax + b`). If the server does not validate that the points we send actually lie on the curve `y^2 = x^3 + 7`, we can force it to perform calculations on a weaker curve of our choice.

## The Vulnerability

The vulnerability is a specific type of Invalid Curve Attack known as a **Singular Curve Attack** (or Cusp Attack).

For secp256k1, the parameter `a = 0`. If we provide a point that satisfies `y^2 = x^3` (effectively setting `b = 0`), the server will perform calculations on this singular curve.

The curve `y^2 = x^3 mod p` is not secure. It is isomorphic to the **Additive Group modulo p**. This means the complex Elliptic Curve Discrete Logarithm Problem (ECDLP) collapses into a simple modular arithmetic equation.

The mapping from a point `P(x, y)` on the singular curve to the integer group is simply:
`map(P) = x / y mod p`

Therefore, the scalar multiplication `Q = d * P` becomes:
`map(Q) = d * map(P) mod p`

## The Logic

We need to recover the secret `d` to solve the challenge.

### Phase 1: Key Recovery
We choose a malicious point `P = (1, 1)`. This point satisfies the singular equation `1^2 = 1^3`.
We send `C1 = (1, 1)` and `C2 = (1, 1)` to the oracle.

The oracle computes `S = C2 - (d * C1)`.
Using the mapping `map(x, y) = x/y`, we can convert this equation to integers:

`map(S) = map(C2) - d * map(C1) mod p`

Substituting our point `(1, 1)`, where `1/1 = 1`:

`(Sx / Sy) = 1 - d * 1 mod p`

We can rearrange this to find `d` instantly:

`d = 1 - (Sx / Sy) mod p`

### Phase 2: Decryption
Once we have `d`, the server enters Phase 2. It provides us with ciphertext `(C1, C2)` encrypted using standard ElGamal on the real curve:

1. `C1 = k * G`
2. `C2 = P + k * Q` (where `Q = d * G`)

To decrypt and get the point `P`, we perform the standard decryption operation:

`P = C2 - (d * C1)`

Note: For Phase 2, we must use a proper ECC library that implements point addition and doubling for secp256k1, as we are no longer on the singular curve.

## Constructing the Solver

I wrote a script using `pwntools` to automate the interaction.

1.  **Exploit Phase 1:** Send `Point(1, 1)` to the server. Receive `S`. Calculate `d` using modular inverse.
2.  **Burn Queries:** The server requires 5 queries in Phase 1. I sent dummy data for the remaining 4 queries to advance the state.
3.  **Decrypt Phase 2:** The server sends 5 rounds of ciphertext. I implemented a small ECC math helper to perform the subtraction `C2 - d*C1` on the valid curve.

## Solution Script

Here is the final solver script. It recovers the key, passes the checks, decrypts the flag, and prints it.

```python
from pwn import *
from Crypto.Util.number import inverse, long_to_bytes

HOST = 'challenges.ctf.sd'
PORT = 33520

P_CURVE = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
A = 0
B = 7

def point_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    (x1, y1), (x2, y2) = p1, p2
    
    if x1 == x2 and y1 != y2:
        return None 
    
    if x1 == x2:
        m = (3 * x1 * x1 + A) * inverse(2 * y1, P_CURVE)
    else:
        m = (y1 - y2) * inverse(x1 - x2, P_CURVE)
    
    m %= P_CURVE
    x3 = (m * m - x1 - x2) % P_CURVE
    y3 = (m * (x1 - x3) - y1) % P_CURVE
    return (x3, y3)

def point_neg(p):
    if p is None: return None
    return (p[0], -p[1] % P_CURVE)

def point_sub(p1, p2):
    return point_add(p1, point_neg(p2))

def scalar_mult(k, p):
    r = None
    while k > 0:
        if k % 2 == 1:
            r = point_add(r, p)
        p = point_add(p, p)
        k //= 2
    return r

def solve():
    r = remote(HOST, PORT)
    fake_point = "Point(1, 1)"
    
    print("[*] Phase 1: Sending Malicious Points...")
    r.sendlineafter(b"Input C1 >", fake_point.encode())
    r.sendlineafter(b"Input C2 >", fake_point.encode())
    
    r.recvuntil(b"Output S > Point(") 
    response = r.recvuntil(b")", drop=True).decode()
    sx, sy = map(int, response.split(', '))
    
    s_mapped = (sx * inverse(sy, P_CURVE)) % P_CURVE
    d = (1 - s_mapped) % P_CURVE

    print(f"[+] Recovered Secret Key d: {d}")

    print("[*] Burning remaining Phase 1 queries...")
    for i in range(4):
        r.sendlineafter(b"Input C1 >", fake_point.encode())
        r.sendlineafter(b"Input C2 >", fake_point.encode())
        r.recvuntil(b"Output S >")

    print("\n[+] Entering Phase 2: Decryption")
    r.recvuntil(b"Phase 2:")
    
    for i in range(5):
        r.recvuntil(b"Given C1: Point(")
        c1_str = r.recvuntil(b")", drop=True).decode()
        c1_x, c1_y = map(int, c1_str.split(', '))
        C1 = (c1_x, c1_y)

        r.recvuntil(b"Given C2: Point(")
        c2_str = r.recvuntil(b")", drop=True).decode()
        c2_x, c2_y = map(int, c2_str.split(', '))
        C2 = (c2_x, c2_y)

        S = scalar_mult(d, C1)
        P = point_sub(C2, S)
        
        answer = f"Point({P[0]}, {P[1]})"
        r.sendlineafter(b"Recovered Point P >", answer.encode())

    r.interactive()

if __name__ == "__main__":
    solve()
```