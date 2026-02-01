---
title: Abusing Encrypted Saves
date: 2026-01-30
tags:
  - crypto
  - Jeanne-d-Hack-CTF-2026
---

**Challenge:** Abusing Encrypted Saves  
**Category:** Crypto  
**Flag:** `JDHACK{M45t3r_0f_A3S_ch34t1nG}`

---

## My initial read / first impressions

We’re given a Python server (`server.py`) that implements a simple rock–paper–scissors game over TCP. We connect via:

```bash
nc crypto.jeanne-hack-ctf.org 5000
```

The menu looks like this:

```text
--- Main Menu ---
1. Play a game
2. View statistics
3. Save progress
4. Load progress
5. Show the flag
6. Exit
```

The goal is to *“achieve 100 consecutive victories”* and then use option 5 to obtain the flag.

The server keeps some stats in a dictionary, something like:

```python
player_progress = {
    "wins": 0,
    "losses": 0,
    "draws": 0,
    "total_games": 0,
    "winrate": 0.0,
}
```

The interesting part (for a crypto challenge) is the way the game **saves** and **loads** your progress. It uses the `cryptography` library with AES in CTR mode:

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = os.urandom(16)
nonce = os.urandom(16)
self.cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
```

This `cipher` object is created **once per connection** and reused for all saves/loads.

When you save your progress (option 3), the server:

1. Formats the stats as zero-padded strings and serializes them to JSON.
2. Prints the JSON **in plaintext**.
3. Encrypts that same JSON with AES-CTR.
4. Prints the base64-encoded ciphertext.

Roughly:

```python
formatted_save = dict(
    (k, f"{v:03}") for k, v in player_progress.items()
)
save = json.dumps(formatted_save)

client_socket.send(f"\nYour actual stats: {save}\n".encode())

encryptor = self.cipher.encryptor()
secure_save = base64.b64encode(
    encryptor.update(save.encode()) + encryptor.finalize()
)
client_socket.send(f"Your save : {secure_save.decode()}\n".encode())
```

To load progress (option 4), it asks for a base64 string, decodes it, and decrypts with:

```python
decryptor = self.cipher.decryptor()
save = json.loads(
    decryptor.update(decoded_save) + decryptor.finalize()
)
player_progress["total_games"] = int(save.get("total_games"))
player_progress["winrate"]     = float(save.get("winrate"))
# etc...
```

Finally, the flag check in `show_flag` is:

```python
if player_progress["total_games"] >= 100 and player_progress["winrate"] == 100.0:
    # print flag
```

So the crypto question is: can we trick the server into loading a forged save with `total_games >= 100` and `winrate == 100.0` without actually winning 100 times?

Spoiler: yes. And we never play a single round.

---

## The Vulnerability

There are two key design flaws:

1. **AES-CTR with a fixed key & nonce per connection**
   The server initializes:

   ```python
   key = os.urandom(16)
   nonce = os.urandom(16)
   self.cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
   ```

   and then repeatedly calls `self.cipher.encryptor()` and `self.cipher.decryptor()` for every save/load. Each call starts CTR from the **same initial counter value**. That means every encryption begins with the same keystream.

2. **Leaking plaintext and ciphertext of the same message**
   For a save, the server prints both:

   * `Your actual stats: <JSON>`  (plaintext)
   * `Your save : <base64>`       (ciphertext)

   Both correspond to the *same* underlying bytes.

AES-CTR works like this:

> `ciphertext = plaintext XOR keystream`

The keystream is determined solely by `(key, nonce, counter)`. If you reuse key+nonce and reset the counter, you reuse the same keystream.

If you know a plaintext–ciphertext pair `(P, C)` under AES-CTR with a fixed `(key, nonce)` then you can compute the keystream:

> `keystream = P XOR C`

Once you know the keystream, you can encrypt **any other** chosen plaintext `P'` of the same length:

> `C' = P' XOR keystream`

When the server decrypts `C'` with the same `(key, nonce)`, it will recover exactly `P'`.

So this challenge degenerates into:
**“Use the known-plaintext save to recover the keystream, then forge a save that encodes 100 wins and 100% winrate.”**

---

## The Logic

Let’s look at the exact JSON used in a fresh connection.

When we connect for the first time and immediately save (without playing), the stats dictionary is all zeros. The server formats each value with `"{:03}"` and then JSON-encodes the dict. So we get something like:

```json
{"wins": "000", "losses": "000", "draws": "000", "total_games": "000", "winrate": "0.0"}
```

Call this byte string `P` (plaintext).

The server encrypts it using AES-CTR with the fixed cipher and gives us `C` (after base64 decoding). As noted:

* `C = P XOR K`
* So `K = P XOR C`

Now we want to craft a fake JSON `P'` that will be accepted by `load_progress` as:

```python
wins        = 100
losses      = 0
draws       = 0
total_games = 100
winrate     = 100.0
```

Remember the loading code:

```python
player_progress["wins"]        = int(save.get("wins"))
player_progress["losses"]      = int(save.get("losses"))
player_progress["draws"]       = int(save.get("draws"))
player_progress["total_games"] = int(save.get("total_games"))
player_progress["winrate"]     = float(save.get("winrate"))
```

So if we send:

```json
{"wins": "100", "losses": "000", "draws": "000", "total_games": "100", "winrate": "100"}
```

we get:

* `int("100")   -> 100`
* `int("000")   -> 0`
* `float("100") -> 100.0`

This satisfies the flag condition! The only subtle requirement is:

> `P'` must be the **same length** as `P`.

In our case:

* `"0.0"` and `"100"` both have length 3, so the JSON strings with all zeros vs all hundreds end up having the same number of characters.
* The exploit script checks this with an assert, but in practice they match nicely.

Once we have `P'` of the same length as `P`, we can create a forged ciphertext:

> `C' = P' XOR K = P' XOR (P XOR C)`

and send base64(`C'`) to the server as a “save file” in option 4. The server will decrypt `C'` with the same AES-CTR keystream and directly recover `P'`, updating the stats to 100 wins / 100 games / 100% winrate.

Then option 5 prints the flag.

---

## Constructing the Exploit

The network protocol is very simple:

1. Server sends a banner and the main menu.
2. You send a number (1–6) followed by a newline.
3. Depending on your choice, it prints some text and possibly asks for input again.

We want to:

1. **Save** once to obtain a known plaintext–ciphertext pair.
2. Use that to compute the keystream locally.
3. **Load** a forged ciphertext that decrypts to our desired JSON.
4. Use **Show the flag**.

I used `pwntools` to keep the interaction convenient.

High-level steps:

1. Connect and synchronize to the first prompt (`"> "`).

2. Send `"3"` to trigger a save.

3. Use `recvuntil("Your actual stats: ")` to skip the menu and read the plaintext JSON line.

4. Use `recvuntil("Your save : ")` and then read the base64 ciphertext line.

5. Decode both; compute `keystream = plaintext XOR ciphertext`.

6. Build `P'`:

   ```python
   desired_save = {
       "wins": "100",
       "losses": "000",
       "draws": "000",
       "total_games": "100",
       "winrate": "100",
   }
   forged_plain = json.dumps(desired_save).encode()
   ```

7. Assert `len(forged_plain) == len(plain_json)` (safety check).

8. Compute `forged_ct = forged_plain XOR keystream` and base64-encode it.

9. Synchronize with the menu again, send `"4"`, and when asked for the encrypted save, send our forged base64.

10. Finally send `"5"` and read the flag.

---

## Solution Script

Here is the final exploit script I used:

```python
from pwn import *
import base64
import json

HOST = "crypto.jeanne-hack-ctf.org"
PORT = 5000

def main():
    r = remote(HOST, PORT)

    r.recvuntil(b"Choose your option:")
    r.recvuntil(b"> ")

    r.sendline(b"3")

    r.recvuntil(b"Your actual stats: ")
    plain_json = r.recvline().strip()

    r.recvuntil(b"Your save : ")
    b64_ct = r.recvline().strip()
    ct = base64.b64decode(b64_ct)

    # Sanity check
    assert len(plain_json) == len(ct), f"len mismatch: {len(plain_json)} vs {len(ct)}"

    keystream = bytes(p ^ c for p, c in zip(plain_json, ct))

    desired_save = {
        "wins": "100",
        "losses": "000",
        "draws": "000",
        "total_games": "100",
        "winrate": "100",
    }
    forged_plain = json.dumps(desired_save).encode()

    assert len(forged_plain) == len(plain_json), "Forged JSON length mismatch!"

    forged_ct = bytes(p ^ k for p, k in zip(forged_plain, keystream))
    forged_b64 = base64.b64encode(forged_ct)

    r.recvuntil(b"Choose your option:")
    r.recvuntil(b"> ")

    r.sendline(b"4")
    r.recvuntil(b"encrypted save:")
    r.recvuntil(b"> ")
    r.sendline(forged_b64)

    r.recvuntil(b"Your stats have been upgraded!")
    r.recvuntil(b"Choose your option:")
    r.recvuntil(b"> ")

    r.sendline(b"5")
    print(r.recvall(timeout=3).decode())

if __name__ == "__main__":
    main()
```

Running this script connects to the server, grabs the original save, recovers the AES-CTR keystream, forges a “perfect” save with 100 wins and 100% winrate, loads it, and finally prints the flag.
