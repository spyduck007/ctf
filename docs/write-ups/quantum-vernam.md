---
title: Quantum Vernam
date: 2025-11-28
tags:
  - crypto
  - LakeCTF-Quals-2025
---

**Challenge:** Quantum vernam  
**Category:** Crypto  
**Flag:** `EPFL{URE_3ITH3R_QU4NTUM_BOSSssss_OR_LINALG_BOSS}`

---

## My initial read / first impressions

We are provided with a Python script `chall.py` and a netcat connection. The premise is a quantum version of the "Vernam Cipher" (also known as the One-Time Pad). In classical cryptography, the One-Time Pad is mathematically unbreakable if implemented correctly. The challenge claims to use "perfect secrecy" to encode qubits.

The code flow is as follows:

1.  The server generates a random Flag and a random Key of the same length.
2.  It generates a random 2x2 unitary matrix called **X**.
3.  It asks us (the attacker) to provide two custom 2x2 matrices: **Gate1** and **Gate2**.
4.  For every bit of the flag:
    - A classical bit becomes a qubit, which means it’s represented as a quantum state. That quantum state can be the quantum version of 0 or the quantum version of 1.
    - It applies our **Gate1**.
    - **Encryption Step:** If the corresponding Key bit is `1`, it applies the matrix **X**. If the Key bit is `0`, it does nothing.
    - It applies our **Gate2**.
    - It measures the result and checks if it matches the original flag.

Our goal is to choose **Gate1** and **Gate2** such that the final measurement _always_ returns the original message bit, regardless of whether the secret key bit was `0` or `1`. If we can do this, we bypass the encryption entirely.

## The Vulnerability

The vulnerability relies on a fundamental concept of Linear Algebra called **Eigenvectors**, and a specific property of Quantum Mechanics regarding **Measurement**.

In this challenge, the encryption process applies the matrix **X** conditionally.

- If Key = 0: State stays the same.
- If Key = 1: State becomes $X \times \text{State}$.

Normally, applying a random matrix $X$ would rotate the qubit to a new state, scrambling the information if you don't know if $X$ was applied or not.

However, every matrix has special vectors called **Eigenvectors**. When a matrix is applied to one of its eigenvectors, the vector doesn't rotate or change direction; it only gets multiplied by a number (a scalar).

In the context of Quantum Mechanics, this scalar is a complex number with a magnitude of 1 (a "phase factor"). The critical flaw here is that **quantum measurement ignores this global phase**.

If our qubit is in an eigenvector state of $X$:

1.  **Key = 0:** The qubit stays as is.
2.  **Key = 1:** The qubit gets multiplied by a phase factor.
3.  **Measurement:** Both states look _identical_ to the measurement device.

Therefore, if we align our qubits with the eigenvectors of $X$, the encryption step (applying $X$) becomes invisible.

## The Logic

To exploit this, we need to perform a "Change of Basis." We want to move from the standard way of writing bits ($0$ and $1$) into the "language" of matrix $X$ (its eigenvectors), and then back again.

### Step 1: Analyze Matrix X

The server gives us the matrix $X$ at the start of the connection. We need to parse this complex matrix and calculate its eigenvectors. Let's say the eigenvectors are $v_0$ and $v_1$.

### Step 2: Construct Gate 1

**Gate1** runs _before_ the encryption. We want this gate to translate our standard bits into eigenvectors.

- If the message is 0, Gate1 should turn it into $v_0$.
- If the message is 1, Gate1 should turn it into $v_1$.

In linear algebra terms, the matrix composed of the eigenvectors (as columns) does exactly this. It maps the standard basis to the eigenbasis.

### Step 3: Construct Gate 2

**Gate2** runs _after_ the encryption. At this point, our qubit is still an eigenvector (or a phase-shifted eigenvector). We need to translate it back to a standard bit so the server can measure it correctly.

- We need to turn $v_0$ back into 0.
- We need to turn $v_1$ back into 1.

This is simply the reverse operation of Gate1. Mathematically, this is the **Inverse** of Gate1. Since we are dealing with unitary matrices, the inverse is just the conjugate transpose matrix.

### Summary of the Attack

1.  We send **Gate1 = Eigenvectors of X**.
2.  The server encrypts. Because the state is an eigenvector, the random key effectively does nothing observable.
3.  We send **Gate2 = Inverse of Gate1**.
4.  The server measures the result, which is now identical to the input message. The flag is printed.

## Solution Script

I wrote a script using `pwntools` and `numpy`. The trickiest part was robustly parsing the complex matrix string provided by the server, as Python's standard split functions struggle with complex number formatting (e.g., `1-2j`). I wrote a custom parser to handle that.

```python
from pwn import *
import numpy as np
import re

HOST = 'chall.polygl0ts.ch'
PORT = 6002

def parse_matrix(matrix_str):
    clean_str = matrix_str.replace('[', ' ').replace(']', ' ').replace('\n', ' ')
    regex = r'[+-]?\d+(?:\.\d+)?(?:e[+-]?\d+)?(?:[+-]\d+(?:\.\d+)?(?:e[+-]?\d+)?j)?j?'
    raw_matches = re.findall(regex, clean_str)
    matches = [m for m in raw_matches if len(m) > 1 or m.isdigit() or 'j' in m]

    values = []
    for m in matches:
        try:
            values.append(complex(m.replace(' ', '')))
        except ValueError:
            continue

    final_values = []
    skip_next = False

    if len(values) == 4:
        final_values = values
    else:
        for i in range(len(values)):
            if skip_next:
                skip_next = False
                continue

            curr_val = values[i]
            if i + 1 < len(values):
                next_val = values[i+1]
                if curr_val.imag == 0 and next_val.real == 0:
                    final_values.append(curr_val + next_val)
                    skip_next = True
                    continue

            final_values.append(curr_val)

    if len(final_values) != 4:
        return None

    return np.array(final_values).reshape(2, 2)

def solve():
    r = remote(HOST, PORT)
    r.recvuntil(b"x = ")
    matrix_str = r.recvuntil(b"You can apply", drop=True).decode().strip()

    X = parse_matrix(matrix_str)
    if X is None:
        return

    eigenvalues, V = np.linalg.eig(X)
    gate1 = V
    gate2 = np.linalg.inv(gate1)

    def send_matrix(mat):
        flat = mat.flatten()
        for val in flat:
            to_send = str(val).replace('(', '').replace(')', '')
            r.sendlineafter(b"matrix element:", to_send.encode())

    send_matrix(gate1)
    send_matrix(gate2)

    r.recvuntil(b"measurement: ")
    measured_bits = r.recvline().decode().strip()

    rest = r.recvall().decode()
    if "EPFL{" in rest:
        flag = re.search(r"(EPFL\{.*?\})", rest).group(1)
        print(flag)
    else:
        print(rest)

if __name__ == "__main__":
    solve()
```
