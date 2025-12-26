---
title: Guess Flag
date: 2025-11-28
tags:
  - crypto
  - LakeCTF-Quals-2025
---

**Challenge:** Guess Flag  
**Category:** Crypto  
**Flag:** `EPFL{15392948299929328383828399923990}`

---

## My initial read / first impressions

We are provided with a Python script `Guessflag.py` and a netcat instance to connect to. The challenge description ("You will never guess the flag") and the source code immediately frame this as a brute-force problem.

The server tells us the flag is **32 digits long**. The code contains a hardcoded (dummy) flag for testing, but on the live server, this will be the real 32-digit secret.

Standard brute force is impossible here. A 32-digit number implies $10^{32}$ possibilities. Even if we could check billions of flags per second, the universe would end before we finished. There must be a logic flaw in how the code checks our input.

## The Vulnerability

I examined the verification logic in `Guessflag.py` closely. This is where the developer made a critical mistake regarding **input validation**:

```python
for char in user_input:
    if char != flag[index]:
        print("Wrong flag!")
        exit()
    index += 1

print("Correct flag!")
```

The code iterates through the characters of `user_input`, comparing them one by one to the `flag`.

Crucially, **it does not check if the length of the user input matches the length of the flag.**

This means the server validates whatever prefix we send it.

1. If the flag is `12345...` and we send just `1`, the loop runs once. `1` matches `1`. The loop finishes. The script prints **"Correct flag!"**.
2. If we send `9`, the loop runs once. `9` does not match `1`. The script prints **"Wrong flag!"** and exits.

This behavior turns an impossible brute-force problem into a trivial "Oracle" attack. We don't need to guess the whole sequence at once; we can guess it one digit at a time.

## The Logic

We can write a script to abuse this "partial validation" behavior. This is essentially a Side-Channel attack where the "side channel" is the specific output message from the server.

The algorithm works like this:

1. Start with an empty string as our `known_flag`.
2. Enter a loop that runs 32 times (once for each digit we need to find).
3. Inside that loop, try every digit from `0` to `9`.
4. Construct a `guess` by combining our `known_flag` + the `current_digit`.
5. Send this guess to the server.
6. **The Check:**
   - If the server responds with **"Correct flag!"**, we know this digit is correct. We add it to our `known_flag` and break the inner loop to move to the next position.
   - If the server responds with **"Wrong flag!"**, we ignore it and try the next digit.

By doing this, we reduce the complexity from $10^{32}$ (impossible) to $32 \times 10$ (320 attempts), which takes only a few seconds.

## Constructing the Solver

I used Python and the `pwntools` library to automate the network interaction. `pwntools` is perfect for this because it handles the socket connections and data streams cleanly.

The script connects to the challenge, reads the initial prompt to clear the buffer, sends our current guess, and checks if the success message appears in the response.

### Solution Script

Here is the final SageMath script. It loads the keys, constructs the large linear system by computing the difference between the two instances, solves for the reused randomness `r`, and decrypts the flag.

```python
from pwn import *
import string
import time

HOST = 'chall.polygl0ts.ch'
PORT = 6001
FLAG_LENGTH = 32
ALPHABET = string.digits

def solve():
    flag_content = ""
    for i in range(FLAG_LENGTH):
        found_digit = False
        for digit in ALPHABET:
            try:
                r = remote(HOST, PORT, level='error')
                r.recvline()
                guess = flag_content + digit
                r.sendline(guess.encode())
                response = r.recvall(timeout=2).decode()
                r.close()
                if "Correct flag!" in response:
                    flag_content += digit
                    found_digit = True
                    break
            except:
                time.sleep(0.5)
        if not found_digit:
            break
    print(f"EPFL{{{flag_content}}}")

if __name__ == "__main__":
    solve()
```

Running the script reveals the digits one by one. The server validates our prefixes, leading us straight to the answer.
