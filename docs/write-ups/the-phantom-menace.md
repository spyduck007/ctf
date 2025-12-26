---
title: The Phantom Menace
date: 2025-11-28
tags:
  - crypto
  - LakeCTF-Quals-2025
---

**Challenge:** The Phantom Menace  
**Category:** Crypto  
**Flag:** `EPFL{y0u_w3r3_r1ght_m4a5t3r_th3_n3g0t14t410n5_w3r3_5h0rt_ot3zhe}`

---

## My initial read / first impressions

We are provided with `chall.py` and a JSON file containing keys. At first glance, this looks like a serious "Learning With Errors" (LWE) challenge. The code implements a cryptosystem very similar to **Kyber**, which is the current standard for post-quantum cryptography.

I checked the parameters immediately, hoping for a "Weak Parameter" attack (like a small `n` or modulus `q`):

```python
# Parameters
q = 3329
n = 512
k = 4
```

These are essentially the parameters for **Kyber-512**. In lattice cryptography, $n=512$ with a module rank of 4 creates a lattice dimension over 2000. This is massive. You cannot solve this using lattice reduction algorithms like LLL or BKZ; the search space is astronomically too large.

I thought I might have to look for a flaw in the random number generator or the polynomial multiplication logic, but the math looked standard.

## The Vulnerability

The vulnerability wasn't in the math—it was in the file handling.

The challenge is named **"The Phantom Menace"**. In the movie, the menace (the trade federation/Sith threat) is largely a manipulation. Here, the "menace" of solving a post-quantum lattice problem is also fake.

I looked at the bottom of `chall.py` where the keys are saved:

```python
keys = {
    "s":s.tolist(),
    "u":u.tolist(),
    "v":v.tolist()
}
```

The script explicitly saves `s` to the public JSON file. In LWE cryptography, `s` is the **Private Key**.

The security of this entire system relies on `s` being secret. If you have `s`, you don't need to break any encryption; you just perform the standard decryption process. The "menace" of the complex math was a phantom; we were given the key to the front door.

## The Logic

Since we have the private key, we just need to implement the decryption function.

### 1. The Decryption Equation

The ciphertext consists of two parts: a vector `u` and a vector `v`.

- **u** is a random value masked by the public key.
- **v** is the message masked by the public key.

To get the message back, we calculate:
**Result = v - (s • u)**

In simple terms: The vector `u` contains a specific random shift. Because we know the private key `s`, we can calculate exactly how much `u` was shifted and subtract that shift from `v`.

### 2. Removing Noise

LWE is "noisy" encryption. The result of the calculation above won't be the exact message; it will be the message plus some small errors.

- If the result is close to 0, the message bit is **0**.
- If the result is close to half the modulus (around 1665), the message bit is **1**.

We just round the numbers to the nearest valid bit to recover the plaintext.

## Solution Script

I wrote a Python script to load the keys and perform the decryption math. I re-implemented the polynomial multiplication logic from the challenge file to ensure compatibility.

```python
import json
import numpy as np

q = 3329
n = 512

def solve():
    try:
        with open('keys.json', 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        try:
            with open('key.json', 'r') as f:
                data = json.load(f)
        except FileNotFoundError:
            return

    s = np.array(data['s'])
    u = np.array(data['u'])
    v = np.array(data['v'])

    def _poly_mul(a, b):
        res = np.convolve(a, b)
        for i in range(n, len(res)):
            res[i - n] = (res[i - n] - res[i]) % q
        return res[:n] % q

    def _vec_poly_mul(v0, v1):
        return sum((_poly_mul(a, b) for a, b in zip(v0, v1))) % q

    s_dot_u = _vec_poly_mul(s, u)
    diff = (v - s_dot_u) % q

    scale = (q + 1) // 2
    bits = []
    for val in diff:
        dist_0 = min(val, q - val)
        dist_1 = min(abs(val - scale), q - abs(val - scale))
        bits.append(0 if dist_0 < dist_1 else 1)

    chars = []
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i+8]
        if len(byte_bits) < 8:
            break
        byte_val = int("".join(map(str, byte_bits)), 2)
        chars.append(chr(byte_val))

    flag = "".join(chars)
    print(flag)

if __name__ == "__main__":
    solve()

```

Running the script instantly decrypts the data, proving that sometimes the best way to break a crypto challenge is to check if the author accidentally gave you the key!
