---
title: Postbox
date: 2026-07-06
tags:
- crypto
- LYKNCTF
---

- **Challenge:** Postbox
- **Category:** Crypto
- **Flag:** `LYKNCTF{1425cea94b9d41aab54366beaf4e16b4}`

---

## My initial read / first impressions

The challenge description says:

```text
A small login service issues encrypted session tokens.

You can request a token, and you can ask the service to check whether a submitted token is structurally acceptable. Somewhere inside the encrypted session data is the flag.
```

Opening the main page just lists the endpoints:

```text
GET  /
GET  /login
POST /decrypt
```

So there are only two useful things to look at: `/login`, which gives us an encrypted token, and `/decrypt`, which checks a token that we submit.

Requesting `/login` returns something like:

```json
{
  "iv": "9d8f098adfb3f01e1889c4a1b7481ca9",
  "ciphertext": "69c6ce4da1d501ab4004e8fac5a8af0e...",
  "note": "AES-128-CBC token. POST manipulated (iv, ciphertext) to /decrypt to learn if the padding is valid."
}
```

The note basically gives away the entire challenge. The token is AES-CBC, and the `/decrypt` endpoint leaks whether the submitted ciphertext has valid padding.

That means this is a classic CBC padding oracle.

## Checking the oracle

Submitting the original token to `/decrypt` gives:

```json
{"ok": true}
```

But if I flip a byte near the end of the ciphertext, the response changes to:

```json
{"error": "bad padding"}
```

That one-bit difference is enough to decrypt the whole token without the key.

The server is not giving us plaintext directly, but it is answering this question over and over:

```text
Does this decrypt to valid PKCS#7 padding?
```

For CBC mode, that is enough.

## The Vulnerability

In AES-CBC decryption, each plaintext block is computed like this:

```text
P_i = D_k(C_i) xor C_{i-1}
```

For the first block, the IV acts like the previous block:

```text
P_0 = D_k(C_0) xor IV
```

The important part is that I can control the previous block. If I submit a forged previous block before a target ciphertext block, then I control what gets XORed with `D_k(C_i)`.

So for a target block, I treat:

```text
I_i = D_k(C_i)
```

as the hidden intermediate value. Then I recover it byte by byte by forcing the decrypted plaintext to have valid PKCS#7 padding.

For example, to recover the last byte, I try all 256 possible values for the last byte of the forged previous block until the server says the padding is valid. Valid padding of `0x01` means:

```text
forged_prev[-1] xor I_i[-1] = 0x01
```

So:

```text
I_i[-1] = forged_prev[-1] xor 0x01
```

Then the real plaintext byte is:

```text
P_i[-1] = I_i[-1] xor real_prev[-1]
```

After that, I move to `0x02 0x02`, then `0x03 0x03 0x03`, and so on until the whole block is recovered.

## Decrypting the token

The first script worked, but it was really slow because it made every oracle request one at a time. Since the token was 6 blocks long, that could mean a lot of requests.

I sped it up by testing guesses in parallel, but the important thing was to keep the oracle strict. My first fast version accepted anything that was not exactly `bad padding`, which caused garbage plaintext because random server weirdness could look like success.

The fixed version only treats this as valid:

```json
{"ok": true}
```

Everything else is either invalid padding or ignored/retried.

The decrypted plaintext came out as:

```text
session: user=guest; role=viewer; flag=LYKNCTF{1425cea94b9d41aab54366beaf4e16b4}
```

So the flag was literally inside the encrypted session data the whole time.

## Solution Script

Here is the final solve script I used. It gets a fresh token from `/login`, uses `/decrypt` as a padding oracle, decrypts the CBC blocks, and stops once it finds the flag.

```python
#!/usr/bin/env python3
import re
import time
import argparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

BLOCK = 16


def chunks(b, n=16):
    return [b[i:i+n] for i in range(0, len(b), n)]


class Oracle:
    def __init__(self, base_url, workers=32, timeout=8, retries=4):
        self.base = base_url.rstrip("/")
        self.workers = workers
        self.timeout = timeout
        self.retries = retries

    def get_token(self):
        r = requests.get(self.base + "/login", timeout=self.timeout)
        r.raise_for_status()
        j = r.json()

        iv = bytes.fromhex(j["iv"])
        ct = bytes.fromhex(j["ciphertext"])

        print("[+] Got token")
        print(f"    iv = {j['iv']}")
        print(f"    ciphertext length = {len(ct)} bytes / {len(ct)//BLOCK} blocks")

        return iv, ct

    def query_status(self, iv, ct):
        payload = {
            "iv": iv.hex(),
            "ciphertext": ct.hex(),
        }

        for _ in range(self.retries):
            try:
                r = requests.post(
                    self.base + "/decrypt",
                    json=payload,
                    timeout=self.timeout,
                )

                try:
                    j = r.json()
                except Exception:
                    time.sleep(0.03)
                    continue

                if j.get("ok") is True:
                    return True

                err = str(j.get("error", "")).lower()
                if "bad padding" in err:
                    return False

                time.sleep(0.03)

            except Exception:
                time.sleep(0.03)

        return None

    def is_valid_padding(self, iv, ct):
        return self.query_status(iv, ct) is True


def make_payload(original_iv, blocks, block_index, forged_prev):
    cur = blocks[block_index]

    if block_index == 0:
        return bytes(forged_prev), cur

    prefix = b"".join(blocks[:block_index - 1])
    return original_iv, prefix + bytes(forged_prev) + cur


def guess_order_for_byte(prev_byte, pad):
    likely_plain = (
        b"abcdefghijklmnopqrstuvwxyz"
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        b"0123456789"
        b"{}_:-=;,. \"'/\\[]()"
    )

    out = []
    seen = set()

    for p in likely_plain:
        g = p ^ prev_byte ^ pad
        if g not in seen:
            out.append(g)
            seen.add(g)

    for g in range(256):
        if g not in seen:
            out.append(g)
            seen.add(g)

    return out


def decrypt_block(oracle, original_iv, blocks, block_index):
    prev = original_iv if block_index == 0 else blocks[block_index - 1]

    intermediate = bytearray(BLOCK)
    plaintext = bytearray(BLOCK)

    print(f"[+] Decrypting block {block_index + 1}/{len(blocks)}")

    for pad in range(1, BLOCK + 1):
        idx = BLOCK - pad
        base = bytearray(BLOCK)

        for j in range(idx + 1, BLOCK):
            base[j] = intermediate[j] ^ pad

        def test_guess(g):
            forged = bytearray(base)
            forged[idx] = g
            tiv, tct = make_payload(original_iv, blocks, block_index, forged)

            if not oracle.is_valid_padding(tiv, tct):
                return None

            # Confirm the same candidate again so a flaky response does not
            # poison the recovered plaintext.
            if not oracle.is_valid_padding(tiv, tct):
                return None

            # Avoid the common pad=1 false positive.
            if pad == 1 and idx > 0:
                check = bytearray(forged)
                check[idx - 1] ^= 1
                civ, cct = make_payload(original_iv, blocks, block_index, check)

                if not oracle.is_valid_padding(civ, cct):
                    return None

            return g

        found = None
        order = guess_order_for_byte(prev[idx], pad)

        for off in range(0, 256, oracle.workers):
            batch = order[off:off + oracle.workers]
            candidates = []

            with ThreadPoolExecutor(max_workers=oracle.workers) as ex:
                futures = [ex.submit(test_guess, g) for g in batch]

                for fut in as_completed(futures):
                    res = fut.result()
                    if res is not None:
                        candidates.append(res)

            if candidates:
                candidates.sort(key=lambda x: order.index(x))
                found = candidates[0]
                break

        if found is None:
            raise RuntimeError(f"Failed at block {block_index + 1}, byte {idx}")

        intermediate[idx] = found ^ pad
        plaintext[idx] = intermediate[idx] ^ prev[idx]

        ch = chr(plaintext[idx]) if 32 <= plaintext[idx] <= 126 else "."
        print(f"    byte {idx:02d}: 0x{plaintext[idx]:02x} {ch!r}", flush=True)

    block_plain = bytes(plaintext)
    print(f"[+] Block plaintext: {block_plain!r}")
    return block_plain


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", nargs="?", default="http://TARGET/")
    ap.add_argument("--workers", type=int, default=32)
    ap.add_argument("--timeout", type=float, default=8)
    ap.add_argument("--retries", type=int, default=4)
    args = ap.parse_args()

    oracle = Oracle(args.url, workers=args.workers, timeout=args.timeout, retries=args.retries)
    iv, ct = oracle.get_token()
    blocks = chunks(ct, BLOCK)

    recovered = b""

    for i in range(len(blocks)):
        recovered += decrypt_block(oracle, iv, blocks, i)

        print("\n[+] Partial plaintext:")
        print(recovered)

        m = re.search(rb"LYKNCTF\{[^}]+\}", recovered)
        if m:
            print("\n[+] FLAG:", m.group(0).decode())
            return

    print("\n[+] Raw plaintext:")
    print(recovered)


if __name__ == "__main__":
    main()
```

Running it prints the recovered session data block by block:

```text
[+] Block plaintext: b'session: user=gu'
[+] Block plaintext: b'est; role=viewer'
[+] Block plaintext: b'; flag=LYKNCTF{1'
[+] Block plaintext: b'425cea94b9d41aab'
[+] Block plaintext: b'54366beaf4e16b4}'
```

Putting those together gives:

```text
session: user=guest; role=viewer; flag=LYKNCTF{1425cea94b9d41aab54366beaf4e16b4}
```

## Why this works

The actual AES key never matters. AES-CBC itself is not broken here; the bug is that the server exposes a padding oracle.

Because `/decrypt` tells us whether the decrypted token has valid PKCS#7 padding, we can repeatedly modify the IV or previous ciphertext block and learn the hidden intermediate AES decryption value one byte at a time.

Once we have that intermediate value, recovering the plaintext is just XORing it with the real previous block.

The full chain is:

```text
/login gives AES-CBC token
    -> /decrypt leaks valid vs invalid padding
    -> padding oracle recovers D_k(C_i) byte by byte
    -> XOR with previous block / IV
    -> plaintext session data
    -> flag
```

## Final flag

```text
LYKNCTF{1425cea94b9d41aab54366beaf4e16b4}
```
