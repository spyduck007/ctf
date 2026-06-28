---
title: The Sound of Noise
date: 2026-06-28
tags:
- crypto
- MntcrlCTF-2026
---

- **Challenge:** The Sound of Noise
- **Category:** Crypto
- **Flag:** `mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ckks_263bc1e7a0c1944b}`

---

## My initial read / first impressions

We are given a crypto challenge with this description:

```text
An encrypted telemetry stream is produced with CKKS, and the service exposes a noisy aggregation endpoint.

It's post quantum secure.
```

So the challenge is very obviously about homomorphic encryption, specifically CKKS.

At first, the description makes it sound like the crypto itself is supposed to be the hard part. CKKS is a lattice-based homomorphic encryption scheme, so "post quantum secure" is technically true.

The files were pretty small:

- `app.py`
- `Dockerfile`
- `requirements.txt`

The important file is `app.py`.

The service gives a menu:

```text
1. Display System Specs
2. Capture Encrypted Signal
3. Run Signal Integrator
4. Exit
```

So we can get the public CKKS context/key, capture an encrypted telemetry stream, and then send ciphertexts to an integration endpoint.

That already sounded suspicious.

## Reading the source

The challenge creates a CKKS context like this:

```python
self.engine = Pyfhel()
self.config = {"scheme": "CKKS", "n": 8192, "scale": 2**30, "qi_sizes": [60, 30, 60]}
self.engine.contextGen(**self.config)
self.engine.keyGen()
```

Then it stores the flag in a vector.

```python
self.n_slots = self.engine.n // 2
self.flag = os.getenv("FLAG", "mntcrl{fake_flag_for_testing}")

self.gain = random.uniform(10.0, 20.0)
self.shift = random.randint(500, 1000)
self.query_count = 0
default_budget = len(self.flag) + 12
self.max_queries = default_budget
```

The flag is not placed at the start of the vector. It gets shifted somewhere between slot `500` and slot `1000`.

The encrypted signal is generated here:

```python
def capture_signal(self):
    wave = np.zeros(self.n_slots)
    for idx, char in enumerate(self.flag):
        wave[self.shift + idx] = float(ord(char))
    return base64.b64encode(self.engine.encrypt(wave).to_bytes()).decode()
```

So the plaintext vector looks basically like:

```text
0 0 0 0 ... ord('m') ord('n') ord('t') ord('c') ... 0 0 0
```

except the start index is randomized.

The system specs endpoint gives us the context and public key:

```python
def get_system_specs(self):
    return {
        "context": base64.b64encode(self.engine.to_bytes_context()).decode(),
        "pub_key": base64.b64encode(self.engine.to_bytes_public_key()).decode(),
        "status": "AGGREGATOR_MODE_ACTIVE",
    }
```

This is normal for homomorphic encryption. The public key lets us encrypt and do public operations, but it does not let us decrypt.

So far, nothing is broken yet.

## The actual bug

The bug is in the signal integrator.

```python
def signal_integrator(self, b64_signal):
    if self.query_count >= self.max_queries:
        return "POWER_DRAINED"

    self.query_count += 1
    try:
        ct = PyCtxt(pyfhel=self.engine)
        ct.from_bytes(base64.b64decode(b64_signal))
        decrypted_vector = self.engine.decrypt(ct)
        total_sum = sum(value.real for value in decrypted_vector)
        return (total_sum * self.gain) + random.uniform(-0.01, 0.01)
    except Exception:
        return "INTEGRATION_ERROR"
```

This endpoint lets us submit any ciphertext.

Then the server decrypts it using the secret key, sums every slot, multiplies the result by some random gain, adds tiny noise, and returns the value.

That is the entire vulnerability.

The server is basically saying:

```text
send me a ciphertext and I will give you a noisy sum of its plaintext
```

That is obviously not a full decryption oracle, but with CKKS homomorphic operations, it is enough.

## Why CKKS helps us

We do not have the secret key, but we do have:

- the CKKS context
- the public key
- the encrypted flag vector

Since CKKS supports homomorphic operations, we can multiply the encrypted flag vector by a plaintext mask.

For example, if we make this mask:

```text
0 0 0 0 1 0 0 0 ...
```

and multiply it with the encrypted flag vector, then only one slot survives.

If the encrypted flag vector is:

```text
0 0 0 0 109 110 116 99 ...
```

and the mask is:

```text
0 0 0 0 1 0 0 0 ...
```

then the masked plaintext becomes:

```text
0 0 0 0 109 0 0 0 ...
```

Then when we send that ciphertext to the server, the integrator decrypts it, sums the slots, multiplies by `gain`, adds tiny noise, and returns something close to:

```text
109 * gain
```

So even though we cannot decrypt locally, we can ask the server for chosen linear measurements of the encrypted flag.

That is the whole solve.

The "post quantum secure" part is bait. The crypto can be post-quantum secure all day, but if the server decrypts attacker-controlled ciphertexts and leaks summaries of the plaintext, the application is cooked.

## Finding the flag start

The flag starts at a random slot:

```python
self.shift = random.randint(500, 1000)
```

So first we need to find where the nonzero data begins.

The service has a query budget:

```python
default_budget = len(self.flag) + 12
self.max_queries = default_budget
```

So we cannot just query every slot from 500 to 1000. We need to be a little careful.

The trick is to binary search using prefix masks.

For a midpoint `mid`, make a mask like:

```text
1 1 1 1 1 ... up to mid ... 0 0 0
```

If `mid` is before the flag starts, the masked sum is basically zero.

If `mid` reaches the first flag byte, the sum suddenly includes `ord('m')`.

Because the gain is between `10` and `20`, the first byte alone gives something around:

```text
ord('m') * gain = 109 * 10 to 109 * 20
```

So around `1090` to `2180`.

The random noise is only `±0.01`.

That means the gap is massive. A threshold like `100` is more than enough.

So binary search gives the start slot in around 9 queries.

In my run:

```text
[+] flag starts at slot 557
```

## Recovering the gain

The endpoint multiplies every result by a random gain:

```python
self.gain = random.uniform(10.0, 20.0)
```

But the first character of the flag is known because the flag format is:

```text
mntcrl{...}
```

So once we know the starting slot, we query only that slot.

That gives:

```text
ord('m') * gain
```

Then:

```python
gain = result / ord("m")
```

In my run:

```text
[+] gain ~= 15.67883584
```

After that, every slot query can be decoded by dividing by the gain and rounding.

## Recovering the flag

Now the rest is very straightforward.

For each slot starting at the flag start:

1. Make a mask with only that slot set to `1.0`.
2. Multiply the encrypted stream by the plaintext mask.
3. Send the masked ciphertext to the integrator.
4. Divide the response by the gain.
5. Round to the nearest integer.
6. Convert to a character.
7. Stop when we get `}`.

The noise is tiny, so rounding works cleanly.

## Solution Script

Here is the final solve script:

```python
import base64
import re
import socket
import ssl
import sys

import numpy as np
from Pyfhel import PyCtxt, Pyfhel


HOST = sys.argv[1] if len(sys.argv) > 1 else "the-sound-of-noise-71a51730611e.c.mntcrl.it"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 443

PROMPT = b"operator@telemetry_node> "


class Remote:
    def __init__(self, host, port):
        raw = socket.create_connection((host, port), timeout=10)
        ctx = ssl._create_unverified_context()
        self.s = ctx.wrap_socket(raw, server_hostname=host)
        self.buf = b""
        self.recv_until(PROMPT)

    def recv_until(self, token):
        while token not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk:
                raise EOFError("connection closed")
            self.buf += chunk
        idx = self.buf.index(token) + len(token)
        out = self.buf[:idx]
        self.buf = self.buf[idx:]
        return out

    def sendline(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.s.sendall(data + b"\n")

    def menu(self, choice):
        self.sendline(str(choice))

    def specs(self):
        self.menu(1)
        text = self.recv_until(PROMPT).decode(errors="replace")
        context = re.search(r"CONTEXT:([A-Za-z0-9+/=]+)", text).group(1)
        pubkey = re.search(r"PUB_KEY:([A-Za-z0-9+/=]+)", text).group(1)
        return context, pubkey

    def capture(self):
        self.menu(2)
        text = self.recv_until(PROMPT).decode(errors="replace")
        return re.search(r"ENCRYPTED_STREAM:([A-Za-z0-9+/=]+)", text).group(1)

    def integrate(self, b64_ct):
        self.menu(3)
        self.recv_until(b"Input Signal Base64: ")
        self.sendline(b64_ct)
        text = self.recv_until(PROMPT).decode(errors="replace")

        if "POWER_DRAINED" in text:
            raise RuntimeError("query budget exhausted")

        if "INTEGRATION_ERROR" in text:
            raise RuntimeError("server rejected ciphertext")

        m = re.search(r"(?m)^\s*([-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?)\s*$", text)

        if not m:
            raise RuntimeError("could not parse integration result:\n" + text)

        return float(m.group(1))


def load_public_he(ctx_b64, pk_b64):
    he = Pyfhel()
    he.from_bytes_context(base64.b64decode(ctx_b64))
    he.from_bytes_public_key(base64.b64decode(pk_b64))
    return he


def encode_mask(he, mask):
    arr = np.asarray(mask, dtype=np.float64)
    if hasattr(he, "encodeFrac"):
        return he.encodeFrac(arr)
    return he.encode(arr)


def masked_stream_b64(he, original_ct_bytes, mask):
    ct = PyCtxt(pyfhel=he)
    ct.from_bytes(original_ct_bytes)
    pt = encode_mask(he, mask)
    ct *= pt
    return base64.b64encode(ct.to_bytes()).decode()


def main():
    r = Remote(HOST, PORT)

    ctx_b64, pk_b64 = r.specs()
    stream_b64 = r.capture()

    he = load_public_he(ctx_b64, pk_b64)
    ct_bytes = base64.b64decode(stream_b64)

    nslots = he.n // 2
    print(f"[+] slots = {nslots}")

    def query_mask(mask):
        return r.integrate(masked_stream_b64(he, ct_bytes, mask))

    def prefix_sum_query(pos):
        mask = np.zeros(nslots, dtype=np.float64)
        mask[:pos + 1] = 1.0
        return query_mask(mask)

    def slot_query(pos):
        mask = np.zeros(nslots, dtype=np.float64)
        mask[pos] = 1.0
        return query_mask(mask)

    lo = 500
    hi = 1000

    while lo < hi:
        mid = (lo + hi) // 2
        y = prefix_sum_query(mid)

        if abs(y) > 100.0:
            hi = mid
        else:
            lo = mid + 1

    start = lo
    print(f"[+] flag starts at slot {start}")

    first = slot_query(start)
    gain = first / ord("m")
    print(f"[+] gain ~= {gain:.8f}")

    flag = "m"
    print(flag, flush=True)

    for i in range(1, 256):
        y = slot_query(start + i)
        val = int(round(y / gain))

        if not (0 <= val < 256):
            raise RuntimeError(f"bad decoded byte at offset {i}: raw={y}, byte={val}")

        ch = chr(val)
        flag += ch
        print(flag, flush=True)

        if ch == "}":
            break

    print("[+] FLAG:", flag)


if __name__ == "__main__":
    main()
```

## Running it

I ran it with:

```bash
python solve.py
```

And got:

```text
[+] slots = 4096
[+] flag starts at slot 557
[+] gain ~= 15.67883584
m
mn
mnt
mntc
mntcr
mntcrl
mntcrl{
mntcrl{n
mntcrl{n3
mntcrl{n3v
mntcrl{n3v3
mntcrl{n3v3r
mntcrl{n3v3r_
mntcrl{n3v3r_g
mntcrl{n3v3r_g1
mntcrl{n3v3r_g1v
mntcrl{n3v3r_g1ve
mntcrl{n3v3r_g1ve_
mntcrl{n3v3r_g1ve_t
mntcrl{n3v3r_g1ve_th
mntcrl{n3v3r_g1ve_th3
mntcrl{n3v3r_g1ve_th3_
mntcrl{n3v3r_g1ve_th3_d
mntcrl{n3v3r_g1ve_th3_d3
mntcrl{n3v3r_g1ve_th3_d3c
mntcrl{n3v3r_g1ve_th3_d3cr
mntcrl{n3v3r_g1ve_th3_d3cr1
mntcrl{n3v3r_g1ve_th3_d3cr1p
mntcrl{n3v3r_g1ve_th3_d3cr1pt
mntcrl{n3v3r_g1ve_th3_d3cr1pto
mntcrl{n3v3r_g1ve_th3_d3cr1ptor
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3r
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rv
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvi
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvic
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_o
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_c
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ck
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ckk
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ckks
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ckks_
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ckks_2
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ckks_26
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ckks_263
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ckks_263b
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ckks_263bc
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ckks_263bc1
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ckks_263bc1e
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ckks_263bc1e7
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ckks_263bc1e7a
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ckks_263bc1e7a0
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ckks_263bc1e7a0c
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ckks_263bc1e7a0c1
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ckks_263bc1e7a0c19
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ckks_263bc1e7a0c194
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ckks_263bc1e7a0c1944
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ckks_263bc1e7a0c1944b
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ckks_263bc1e7a0c1944b}
[+] FLAG: mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ckks_263bc1e7a0c1944b}
```

And that gives the flag:

```text
mntcrl{n3v3r_g1ve_th3_d3cr1ptor_s3rvice_of_ckks_263bc1e7a0c1944b}
```

## Why this works

This is not breaking CKKS.

The cryptography is doing what it is supposed to do. The problem is that the service gives us:

1. the encrypted flag vector,
2. the public context/key,
3. and a decryption-based aggregation endpoint.

Because the aggregation endpoint accepts attacker-controlled ciphertexts, we can use homomorphic plaintext masks to isolate individual slots of the encrypted flag.

The endpoint only returns a noisy sum, but the noise is basically nothing compared to ASCII values multiplied by the gain.

So the exploit is:

```text
encrypted flag
    *
plaintext mask
    =
encrypted single character
```

Then the server decrypts it for us and leaks the value through the sum.