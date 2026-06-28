---
title: The Sound of Noise 2
date: 2026-06-28
tags:
- crypto
- MntcrlCTF-2026
---

- **Challenge:** The Sound of Noise 2
- **Category:** Crypto
- **Flag:** `mntcrl{133742009}`

---

## My initial read / first impressions

We are given an online audit service and the description says:

```text
A fast and secure online audit service. It is so secure that it performs calculations on encrypted data.
```

So right away this sounds like a homomorphic encryption challenge. The files are pretty small:

- `app.py`
- `Dockerfile`
- `docker-compose.yml`

The actual service is in `app.py`, and it uses CKKS through Pyfhel.

At startup, the server generates a CKKS context, keys, and a secret vector:

```python
HE = Pyfhel()
HE.contextGen(scheme='CKKS', n=8192, scale=2**40, qi_sizes=[60, 40, 60])
HE.keyGen(); HE.relinKeyGen(); HE.rotateKeyGen()

PUB_KEY = HE.to_bytes_public_key().hex()
CONTEXT = HE.to_bytes_context().hex()

SECRET_W = [random.randint(100, 500) for _ in range(8)]
THRESHOLD = 250000.0
```

The service also prints the public CKKS context, the public key, and this thing called `PUB_PARAM_A`.

```python
print(f"CONTEXT:{CONTEXT}")
print(f"PUBKEY:{PUB_KEY}")
print(f"PUB_PARAM_A:{json.dumps(PUB_A)}")
```

The important part is that the flag number is hidden inside a dot product.

```python
FLAG_NUMBER = int(os.getenv("FLAG", "mntcrl{134001209}").split("{")[1].split("}")[0])

while True:
    PUB_A = [random.randint(1000, 5000) for _ in range(7)]
    partial_sum = sum(w * a for w, a in zip(SECRET_W[:7], PUB_A))
    remainder = FLAG_NUMBER - partial_sum
    if remainder > 0 and remainder % SECRET_W[7] == 0:
        PUB_A.append(remainder // SECRET_W[7])
        break
```

So the flag is basically:

```python
sum(SECRET_W[i] * PUB_A[i] for i in range(8))
```

That means if we can recover the 8 secret weights, we can calculate the flag.

## Understanding the service

The menu has three useful options:

```text
1. Get Sample
2. IV Diagnostic
3. Secure Audit
```

Option 1 gives a sample:

```python
def get_sample(self):
    iv_vec = np.array([float(b) for b in key] + [0.0]*4, dtype=np.float64)
    ctxt_iv = HE.encrypt(iv_vec)
    val_v = np.random.uniform(10.0, 50.0, 8)
    cipher = AES.new(nonce, AES.MODE_GCM, nonce=key)
    ct, tag = cipher.encrypt_and_digest(val_v.tobytes())
    return {"ct": ct.hex(), "tag": tag.hex(), "ctxt_iv": ctxt_iv.to_bytes().hex(), "val": val_v.tolist()}
```

This gives us:

- AES-GCM ciphertext
- AES-GCM tag
- encrypted CKKS IV vector
- plaintext value `val`

That last part is already very suspicious. We get the plaintext and ciphertext for the same AES-GCM encryption.

Also, the AES setup is broken:

```python
nonce = os.urandom(32)
key = b"3IaHuhUT5jBm"
cipher = AES.new(nonce, AES.MODE_GCM, nonce=key)
```

The variable names are confusing, but the important part is this:

- AES key = random 32 bytes called `nonce`
- GCM nonce = constant `b"3IaHuhUT5jBm"`

So the GCM nonce is reused for every sample.

That is bad.

Option 3 is the actual audit:

```python
def audit(self, ct_hex, tag_hex, ctxt_iv_bytes, ctxt_mod_bytes):
    c_iv = PyCtxt(pyfhel=HE)
    c_iv.from_bytes(bytes.fromhex(ctxt_iv_bytes))
    c_mod = PyCtxt(pyfhel=HE)
    c_mod.from_bytes(bytes.fromhex(ctxt_mod_bytes))
    res_iv = HE.decrypt(c_iv + c_mod)[:12]
    iv_f = bytes([max(0, min(255, int(round(b)))) for b in res_iv])

    cipher = AES.new(nonce, AES.MODE_GCM, nonce=iv_f)
    pt = cipher.decrypt_and_verify(bytes.fromhex(ct_hex), bytes.fromhex(tag_hex))
            
    x_v = np.frombuffer(pt, dtype=np.float64)
    x_ctxt = HE.encrypt(x_v)
    w_pt = HE.encode(np.array(SECRET_W, dtype=np.float64))
    prod = x_ctxt * w_pt
    for i in range(1, 8):
        t = prod.copy(); HE.rotate(t, i); prod += t
    return "EXCEEDED" if HE.decrypt(prod)[0] > THRESHOLD else "BELOW"
```

The audit decrypts our AES-GCM message, interprets it as 8 doubles, multiplies it by the secret weights, does some CKKS rotations, and only tells us whether the final value is above a threshold.

So the challenge becomes:

1. Forge valid AES-GCM messages.
2. Send chosen vectors into the audit.
3. Use the threshold oracle to recover `SECRET_W`.

## The AES-GCM bug

AES-GCM should never reuse the same nonce with the same key.

Here, every sample uses the same GCM nonce:

```python
key = b"3IaHuhUT5jBm"
cipher = AES.new(nonce, AES.MODE_GCM, nonce=key)
```

And option 1 gives us known plaintext/ciphertext pairs.

Since GCM uses CTR mode for encryption, reusing the nonce reuses the keystream. So from one sample we can recover the keystream for the 8 doubles:

```python
keystream = ciphertext ^ plaintext
```

That lets us encrypt any 8-double vector we want.

But GCM also has authentication tags, so we still need to forge a valid tag.

Because we have multiple known plaintext/ciphertext/tag pairs with the same GCM nonce, we can recover the GHASH key `H`. Once we have `H`, the tag is basically:

```text
tag = tag_mask ^ GHASH(H, ciphertext)
```

So we can compute valid tags for our forged ciphertexts.

This gives full chosen-input access to the audit function.

## The CKKS part

At first, the audit looks like a normal dot product.

```python
x_v = np.frombuffer(pt, dtype=np.float64)
x_ctxt = HE.encrypt(x_v)
w_pt = HE.encode(np.array(SECRET_W, dtype=np.float64))
prod = x_ctxt * w_pt
for i in range(1, 8):
    t = prod.copy(); HE.rotate(t, i); prod += t
return "EXCEEDED" if HE.decrypt(prod)[0] > THRESHOLD else "BELOW"
```

The obvious idea is to isolate one weight at a time.

For example, if I want to test `SECRET_W[0]`, I send:

```python
x = [THRESHOLD / guess, 0, 0, 0, 0, 0, 0, 0]
```

Then the audit tells me whether the result is above `250000`, which tells me whether the weight is above or below my guess.

Since each weight is between 100 and 500, a binary search should recover each weight.

This almost works, but there is one annoying detail.

## The part that baited me

The loop does not rotate the original product each time.

It does this:

```python
prod = x_ctxt * w_pt
for i in range(1, 8):
    t = prod.copy()
    HE.rotate(t, i)
    prod += t
```

Since `prod` is updated every loop, each later rotation is rotating the accumulated value, not just the original vector.

That means the final slot 0 is not simply:

```text
w0*x0 + w1*x1 + w2*x2 + ...
```

Instead, the slots get counted multiple times.

The counts are the number of ways each index can be created by subset sums of the rotations `1..7`.

For the first 8 slots, the counts are:

```python
[1, 1, 1, 2, 2, 3, 4, 5]
```

So the audit is effectively checking:

```text
1*w0*x0 + 1*w1*x1 + 1*w2*x2 + 2*w3*x3 + 2*w4*x4 + 3*w5*x5 + 4*w6*x6 + 5*w7*x7 > 250000
```

This is why my first attempt kept recovering `500` for the later slots. I was searching in the right weight range, but I forgot that the later slots were multiplied by extra rotation counts.

The fix is simple.

When testing weight `i`, use:

```python
x[i] = THRESHOLD / (count[i] * (guess + 0.5))
```

Then the oracle checks whether:

```text
SECRET_W[i] > guess + 0.5
```

Since the weights are integers, this gives a clean binary search.

## Recovering the flag

Once the weights are recovered, the flag number is just:

```python
flag_num = sum(w * a for w, a in zip(weights, pub_a))
```

From my run:

```text
[+] PUB_PARAM_A = [4804, 1714, 1138, 3139, 2740, 4752, 1325, 449516]
[+] weights = [126, 321, 371, 428, 298, 499, 317, 283]
[+] flag number = 133742009
```

So the flag is:

```text
mntcrl{133742009}
```

## Solution Script

Here is the final solve script.

```python
import json
import re
import socket
import ssl
import struct

import numpy as np
from Pyfhel import Pyfhel


HOST = "the-sound-of-noise-2-0c974570c151.c.mntcrl.it"
PORT = 443
THRESHOLD = 250000.0

R = 0xE1000000000000000000000000000000
ONE = 1 << 127

ROT_COUNTS = [1, 1, 1, 2, 2, 3, 4, 5]


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def gf_mul(x, y):
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ R
        else:
            v >>= 1
    return z


def gf_pow(x, n):
    out = ONE
    while n:
        if n & 1:
            out = gf_mul(out, x)
        x = gf_mul(x, x)
        n >>= 1
    return out


def gf_inv(x):
    if x == 0:
        raise ZeroDivisionError("inverse of zero")
    return gf_pow(x, (1 << 128) - 2)


def trim(p):
    p = p[:]
    while p and p[-1] == 0:
        p.pop()
    return p


def poly_divmod(a, b):
    a = trim(a)
    b = trim(b)

    q = [0] * max(0, len(a) - len(b) + 1)
    inv_lc = gf_inv(b[-1])

    while len(a) >= len(b) and a:
        d = len(a) - len(b)
        coef = gf_mul(a[-1], inv_lc)
        q[d] ^= coef

        for i, bc in enumerate(b):
            a[d + i] ^= gf_mul(coef, bc)

        a = trim(a)

    return trim(q), trim(a)


def poly_gcd(a, b):
    a = trim(a)
    b = trim(b)

    while b:
        _, r = poly_divmod(a, b)
        a, b = b, r

    inv_lc = gf_inv(a[-1])
    return [gf_mul(c, inv_lc) for c in a]


def blocks16(data):
    assert len(data) % 16 == 0
    return [
        int.from_bytes(data[i:i + 16], "big")
        for i in range(0, len(data), 16)
    ]


def ghash(H, ciphertext):
    y = 0
    length_block = struct.pack(">QQ", 0, len(ciphertext) * 8)

    for b in blocks16(ciphertext) + [int.from_bytes(length_block, "big")]:
        y = gf_mul(y ^ b, H)

    return y


def diff_poly(c1, t1, c0, t0):
    b1 = blocks16(c1)
    b0 = blocks16(c0)
    assert len(b1) == len(b0)

    n = len(b1) + 1
    coeff = [0] * (n + 1)
    coeff[0] = t1 ^ t0

    for j, (x, y) in enumerate(zip(b1, b0)):
        coeff[n - j] ^= x ^ y

    return trim(coeff)


def recover_h(samples):
    base = samples[0]
    c0 = base["ct_bytes"]
    t0 = base["tag_int"]

    g = None

    for s in samples[1:]:
        p = diff_poly(s["ct_bytes"], s["tag_int"], c0, t0)
        if not p:
            continue

        g = p if g is None else poly_gcd(g, p)

        if len(g) == 2 and g[1] == ONE:
            return g[0]

    raise RuntimeError("Could not recover GCM H")


class Remote:
    def __init__(self):
        raw = socket.create_connection((HOST, PORT))
        ctx = ssl.create_default_context()
        self.s = ctx.wrap_socket(raw, server_hostname=HOST)
        self.buf = b""

    def recv_until(self, marker=b"> "):
        while marker not in self.buf:
            chunk = self.s.recv(65536)
            if not chunk:
                raise EOFError("connection closed")
            self.buf += chunk

        idx = self.buf.index(marker) + len(marker)
        out = self.buf[:idx]
        self.buf = self.buf[idx:]
        return out

    def sendline(self, line):
        if isinstance(line, str):
            line = line.encode()
        self.s.sendall(line + b"\n")


def parse_intro(data):
    text = data.decode(errors="replace")

    context_hex = re.search(r"CONTEXT:([0-9a-fA-F]+)", text).group(1)
    pubkey_hex = re.search(r"PUBKEY:([0-9a-fA-F]+)", text).group(1)
    pub_a = json.loads(re.search(r"PUB_PARAM_A:(\[.*?\])", text).group(1))

    return context_hex, pubkey_hex, pub_a


def get_sample(r):
    r.sendline("1")
    out = r.recv_until()

    m = re.search(rb"\{.*\}", out, re.S)
    if not m:
        raise RuntimeError(f"Could not parse sample:\n{out!r}")

    s = json.loads(m.group(0).decode())
    s["ct_bytes"] = bytes.fromhex(s["ct"])
    s["tag_int"] = int.from_bytes(bytes.fromhex(s["tag"]), "big")
    return s


def make_he(context_hex, pubkey_hex):
    HE = Pyfhel()
    HE.from_bytes_context(bytes.fromhex(context_hex))
    HE.from_bytes_public_key(bytes.fromhex(pubkey_hex))
    return HE


def make_zero_mod_hex(HE):
    zero = HE.encrypt(np.zeros(16, dtype=np.float64))
    return zero.to_bytes().hex()


def forge_plaintext(sample0, H, tag_mask, plaintext_bytes):
    known_pt = np.array(sample0["val"], dtype=np.float64).tobytes()
    keystream = xor_bytes(sample0["ct_bytes"], known_pt)

    forged_ct = xor_bytes(plaintext_bytes, keystream)
    forged_tag = tag_mask ^ ghash(H, forged_ct)

    return forged_ct.hex(), forged_tag.to_bytes(16, "big").hex()


def audit(r, ct_hex, tag_hex, ctxt_iv_hex, cmod_hex):
    r.sendline("3")
    r.sendline(ct_hex)
    r.sendline(tag_hex)
    r.sendline(ctxt_iv_hex)
    r.sendline(cmod_hex)

    out = r.recv_until().decode(errors="replace")

    if "EXCEEDED" in out:
        return True
    if "BELOW" in out:
        return False

    raise RuntimeError(f"Audit failed:\n{out}")


def weight_greater_than(r, idx, count, guess, sample0, H, tag_mask, cmod_hex):
    x = [0.0] * 8
    x[idx] = THRESHOLD / (count * (guess + 0.5))

    pt = np.array(x, dtype=np.float64).tobytes()
    ct_hex, tag_hex = forge_plaintext(sample0, H, tag_mask, pt)

    return audit(r, ct_hex, tag_hex, sample0["ctxt_iv"], cmod_hex)


def recover_weight(r, idx, count, sample0, H, tag_mask, cmod_hex):
    lo, hi = 100, 500

    while lo < hi:
        mid = (lo + hi) // 2

        if weight_greater_than(r, idx, count, mid, sample0, H, tag_mask, cmod_hex):
            lo = mid + 1
        else:
            hi = mid

    return lo


def main():
    r = Remote()

    intro = r.recv_until()
    context_hex, pubkey_hex, pub_a = parse_intro(intro)

    print("[+] Connected")
    print("[+] PUB_PARAM_A =", pub_a)

    print("[+] Collecting GCM nonce-reuse samples...")
    samples = []
    H = None

    for _ in range(12):
        samples.append(get_sample(r))

        if len(samples) >= 3:
            try:
                H = recover_h(samples)
                break
            except RuntimeError:
                pass

    if H is None:
        raise RuntimeError("Failed to recover GCM H")

    print("[+] Recovered GCM H =", hex(H))

    tag_mask = samples[0]["tag_int"] ^ ghash(H, samples[0]["ct_bytes"])

    for s in samples:
        assert s["tag_int"] ^ ghash(H, s["ct_bytes"]) == tag_mask

    print("[+] GCM tag mask verified")

    HE = make_he(context_hex, pubkey_hex)
    cmod_hex = make_zero_mod_hex(HE)

    print("[+] Using accumulated-rotation counts =", ROT_COUNTS)

    print("[+] Recovering SECRET_W...")
    weights = []

    for i, count in enumerate(ROT_COUNTS):
        w = recover_weight(r, i, count, samples[0], H, tag_mask, cmod_hex)
        weights.append(w)
        print(f"    w[{i}] = {w}")

    flag_num = sum(w * a for w, a in zip(weights, pub_a))

    print("[+] weights =", weights)
    print("[+] flag number =", flag_num)
    print(f"mntcrl{{{flag_num}}}")


if __name__ == "__main__":
    main()
```

Running it:

```bash
python solve.py
```

Output:

```text
[+] Connected
[+] PUB_PARAM_A = [4804, 1714, 1138, 3139, 2740, 4752, 1325, 449516]
[+] Collecting GCM nonce-reuse samples...
[+] Recovered GCM H = 0x3ae0cacaa9fc0d8ab75489fbb20a7004
[+] GCM tag mask verified
[+] Using accumulated-rotation counts = [1, 1, 1, 2, 2, 3, 4, 5]
[+] Recovering SECRET_W...
    w[0] = 126
    w[1] = 321
    w[2] = 371
    w[3] = 428
    w[4] = 298
    w[5] = 499
    w[6] = 317
    w[7] = 283
[+] weights = [126, 321, 371, 428, 298, 499, 317, 283]
[+] flag number = 133742009
mntcrl{133742009}
```

And that gives the flag.