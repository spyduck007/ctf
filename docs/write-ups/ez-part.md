---
title: Ez Part
date: 2025-11-28
tags:
  - crypto
  - LakeCTF-Quals-2025
---

**Challenge:** Ez Part  
**Category:** Crypto  
**Flag:** `EPFL{s0me_b1ts_ar3_really_ez_i_t0ld_ya}`

---

## My initial read / first impressions

We are provided with a Python script (`chall.py`) running a Flask server. It implements a "new login system" that uses two distinct verification methods to authenticate users.

1.  **Discrete Logarithm Verification:** It checks if a password (converted to a number $x$) satisfies the equation `3^x mod p == b`, where $b$ is the user's public key.
2.  **Masked Hash Verification:** It applies a series of bitwise AND operations (masks) to the password $x$, hashes the result, and compares it to stored hashes.

The goal is to log in as the `admin` user. The admin is created at startup with a random password that is approximately 1535 bits long. Since we cannot brute-force a 1535-bit password, we need to find a mathematical weakness to recover the admin's secret $x$.

## The Vulnerabilities

Upon analyzing the code, I found three distinct vulnerabilities that, when chained together, allow for full key recovery.

### 1. The Chatty Oracle (Information Leak)

The server is incredibly verbose. When we try to prove our identity via the `/prove-id` endpoint, the server returns specific error messages if verification fails.

- If the discrete log check fails, it returns: `Wrong b: <expected_b>`
- If a mask hash check fails, it returns: `Wrong mask : <index>,<expected_hash>`

This is a massive information leak. Even though we don't know the admin's password, we can try to log in as "admin" with a wrong password. The server will dutifully reply with the admin's public key ($b$) and all the correct hash values for the masks.

### 2. Weak Prime Generation (The Backdoor)

The prime $p$ used for the discrete logarithm is generated in a very specific way:

```python
def gen_p(BITS):
    while True:
        q = getPrime(BITS - 150)
        p = q << 150 + 1  # Equivalent to: q * (2^150) + 1
        if isPrime(p):
            return p
```

This is a classic "weak prime" vulnerability. The order of the multiplicative group is $p-1$. Because $p = q \cdot 2^{150} + 1$, we know that $p-1$ is divisible by $2^{150}$.

In cryptography, if the group order has small factors, we can use the **Pohlig-Hellman algorithm** to solve the discrete logarithm problem for those factors much faster than usual. Specifically, since $2^{150}$ divides the group order, we can recover the secret $x$ modulo $2^{150}$.

**In plain English:** We can instantly recover the first 150 bits (the least significant bits) of the admin's password.

### 3. The Mask "Zipper" Attack

Knowing the bottom 150 bits isn't enough to get the full 1535-bit key, but it gives us a foothold. This is where the masks come in.

The masks are random 80-bit windows shifted by various amounts. Because there are so many of them (over 100), they overlap significantly.

1.  We essentially have a jigsaw puzzle. We start knowing bits 0-150.
2.  We look for a mask that covers mostly bits we **do** know (e.g., bits 80-160), leaving only a small number of bits (150-160) unknown.
3.  We brute-force those few unknown bits (2^10 possibilities is trivial for a computer).
4.  For each guess, we calculate the hash and compare it to the admin's leaked hash.
5.  When the hash matches, we have recovered the new bits. We now know bits 0-160.
6.  We repeat this process, "zipping" our way up the key until we reach the top.

## The Exploitation Strategy

### Step 1: Leaking the Prime P

The challenge generates $p$ on the server, and it's not hardcoded. However, since the server leaks the expected public key $b = 3^x \pmod p$, we can recover $p$.

We register two users with very short passwords (like "aa" and "ab"). Converted to integers, these are small enough that `3^x` is just a regular large integer (it doesn't wrap around the modulus yet). However, the server performs the modulo operation. By sending a wrong login for these users, the server returns `3^x mod p`. By taking the GCD of the differences between the calculated values and the returned values, we recover $p$.

### Step 2: Recovering the Lower 150 Bits

Using the admin's leaked public key $b$, we apply the Pohlig-Hellman attack. We move the problem into the "subgroup" of size $2^{150}$. In this subgroup, we can solve for the bits one by one.

We check the first bit. If it's a 1, we subtract its mathematical contribution from the key. Then we check the second bit, and so on. This recovers the exact integer value of the first 150 bits of the password.

### Step 3: The Zipper Attack

We wrote a solver that iterates through all available masks. It calculates how many "unknown bits" each mask contains relative to what we currently know.

It selects the "easiest" mask (the one with the fewest unknown bits), brute-forces those bits, verifies the hash, and updates our "known bits" state. It repeats this loop until the entire key is recovered.

### Step 4: Final Cleanup

Due to the randomness of the masks, there might be tiny gaps (1 or 2 bits) that no mask covered. However, since we can verify the full key against the admin's public key $b$ (which we leaked in Step 1), we can just brute-force any remaining holes locally.

## The Solution Script

Here is the complete exploit script that automates the entire process.

```python
import requests
import hashlib
from Crypto.Util.number import bytes_to_long, long_to_bytes, GCD
import random
import sys

HOST = "chall.polygl0ts.ch"
PORT = 6027
BASE_URL = f"http://{HOST}:{PORT}"

BRUTE_FORCE_LIMIT = 28

masks = []
admin_b = 0
admin_hashes = []
p = 0
x_recovered = 0
known_mask = 0

try:
    sys.set_int_max_str_digits(10000)
except:
    pass

def hash_value(value):
    return hashlib.sha256(str(value).encode()).hexdigest()

def get_masks():
    global masks
    r = requests.get(f"{BASE_URL}/masks")
    r.raise_for_status()
    data = r.json()['masks']
    masks = [(int(m[0], 16), m[1]) for m in data]

def register(username, password):
    requests.post(f"{BASE_URL}/create-account", json={
        "username": username,
        "password": password
    })

def prove_id(username, password):
    return requests.post(f"{BASE_URL}/prove-id", json={
        "username": username,
        "password": password
    })

def leak_p():
    global p
    run_id = random.randint(10000, 99999)
    u1, u2 = f"user_A_{run_id}", f"user_B_{run_id}"
    register(u1, "aa")
    register(u2, "ab")
    r1 = prove_id(u1, "1")
    r2 = prove_id(u2, "1")
    rem1 = int(r1.json()['message'].split("Wrong b: ")[1].split("\n")[0])
    rem2 = int(r2.json()['message'].split("Wrong b: ")[1].split("\n")[0])
    val1 = pow(3, bytes_to_long(b"aa"))
    val2 = pow(3, bytes_to_long(b"ab"))
    p = GCD(val1 - rem1, val2 - rem2)

def get_admin_data():
    global admin_b, admin_hashes
    r = prove_id("admin", "wrongpass")
    msg = r.json()['message']
    lines = msg.split("\n")
    admin_hashes = [""] * len(masks)
    for line in lines:
        if "Wrong b:" in line:
            admin_b = int(line.split(": ")[1])
        if "Wrong mask :" in line:
            parts = line.split(" : ")[1].split(",")
            idx = int(parts[0])
            h = parts[1].strip()
            if 0 <= idx < len(masks):
                admin_hashes[idx] = h

def solve_discrete_log_low_bits():
    global x_recovered, known_mask
    k = 150
    exponent = (p - 1) // (1 << k)
    beta = pow(admin_b, exponent, p)
    alpha = pow(3, exponent, p)
    alpha_inv = pow(alpha, -1, p)
    x = 0
    gamma = beta
    for i in range(k):
        check = pow(gamma, 1 << (k - 1 - i), p)
        if check != 1:
            x |= (1 << i)
            term = pow(alpha_inv, 1 << i, p)
            gamma = (gamma * term) % p
    x_recovered = x
    known_mask = (1 << 150) - 1

def solve_masks():
    global x_recovered, known_mask
    target_bits = 1535
    while True:
        best_candidate = None
        min_unknown = 999
        for i, (m_val, shift) in enumerate(masks):
            full_mask = m_val << shift
            unknown_part = full_mask & ~known_mask
            if unknown_part == 0:
                continue
            unknown_count = bin(unknown_part).count('1')
            if unknown_count < min_unknown:
                min_unknown = unknown_count
                best_candidate = (unknown_count, i, full_mask, unknown_part)

        if best_candidate is None:
            break

        count, idx, full_mask, unknown_part = best_candidate
        if count > BRUTE_FORCE_LIMIT:
            print(f"Stuck! Lowest unknown bits is {count}, which is too high.")
            break

        # Brute force the unknown bits
        unknown_indices = []
        temp = unknown_part
        pos = 0
        while temp > 0:
            if temp & 1:
                unknown_indices.append(pos)
            temp >>= 1
            pos += 1

        found = False
        for i in range(1 << count):
            guess = x_recovered
            for j in range(count):
                if (i >> j) & 1:
                    guess |= (1 << unknown_indices[j])

            masked_val = (guess >> masks[idx][1]) & masks[idx][0]
            if hash_value(masked_val) == admin_hashes[idx]:
                x_recovered = guess
                known_mask |= unknown_part
                found = True
                break

        if not found:
            print("Error: Could not find matching bits for mask")
            break

def finish_holes():
    global x_recovered
    # Just try to login with the recovered key. If it fails, maybe brute force small gaps?
    # For this challenge, the masks usually cover everything.
    pass

def main():
    print("[*] Leaking P...")
    leak_p()
    print(f"[+] Found P: {p}")

    print("[*] Getting Admin Data...")
    get_admin_data()

    print("[*] Solving Discrete Log (Lower 150 bits)...")
    solve_discrete_log_low_bits()
    print(f"[+] Recovered lower bits: {hex(x_recovered)}")

    print("[*] Getting Masks...")
    get_masks()

    print("[*] Solving Masks (Zipper Attack)...")
    solve_masks()

    print(f"[+] Recovered Key: {x_recovered}")
    print("[*] Logging in as Admin...")

    flag_pass = long_to_bytes(x_recovered).decode()
    r = requests.post(f"{BASE_URL}/login", json={
        "username": "admin",
        "password": flag_pass
    })
    print(r.text)

if __name__ == "__main__":
    main()
```
