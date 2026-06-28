---
title: EDDSA
date: 2026-06-28
tags:
- crypto
- MntcrlCTF-2026
---

- **Challenge:** EDDSA
- **Category:** Crypto

---

## My initial read / first impressions

We are given a remote service and the challenge description says:

```text
Just an easy way to get a sign collision.
```

So from the start, this sounds like we need to produce two different messages that verify under the same signature.

The service was pretty small. It had a menu where we could register a user with our own Ed25519 public key, and then later submit two different messages with a signature. If the same signature verified for both messages, it would give the flag.

At first, this sounds impossible if Ed25519 is being used correctly. A signature should be tied to the message, so a valid signature for one message should not also verify for a different one.

But the important detail is that the server lets us choose the public key ourselves.

That means this is probably not about breaking Ed25519 normally. It is about giving the verifier a weird public key.

## The Vulnerability

The bug is related to small-order points on Ed25519.

Normally, Ed25519 verification checks something like:

```text
S * G = R + H(R, A, M) * A
```

Where:

- `A` is the public key
- `R` is part of the signature
- `S` is the other part of the signature
- `M` is the message
- `G` is the generator point

The message is included inside the hash, so changing the message should change the verification equation.

But the implementation being used multiplies both sides by the cofactor `8`, so the check becomes more like:

```text
8 * S * G = 8 * R + H(R, A, M) * 8 * A
```

This is usually done to handle subgroup issues, but it also means that if we choose a public key `A` where:

```text
8 * A = 0
```

Then the message-dependent part disappears.

So the equation becomes:

```text
8 * S * G = 8 * R
```

Now the message does not matter anymore.

That is the whole challenge.

## The Trick

Since the service lets us register any public key, we can register the Ed25519 identity point.

The compressed identity point is:

```python
b"\x01" + b"\x00" * 31
```

In hex, that is:

```text
0100000000000000000000000000000000000000000000000000000000000000
```

Then we also set `R` in the signature to the identity point, and set `S = 0`.

So the signature is:

```text
R || S
```

Where:

```python
R = identity
S = 0
```

That makes the final signature:

```python
identity + b"\x00" * 32
```

Now verification becomes:

```text
8 * 0 * G = 8 * identity
```

Which is basically:

```text
0 = 0
```

So the same signature verifies for any message.

That means we can submit two different messages like:

```text
hello
world
```

With the exact same signature, and the server accepts it as a valid collision.

## The Logic

The main thing that makes this work is that we control the public key.

If the server generated the keypair itself, this would not work because normal Ed25519 public keys are not supposed to be small-order points.

But because we can register our own public key, we can give it a malicious one.

The values are very simple:

```python
IDENTITY = b"\x01" + b"\x00" * 31
PUBKEY_HEX = IDENTITY.hex()
SIG_HEX = (IDENTITY + b"\x00" * 32).hex()
```

Then the attack flow is:

1. Connect to the remote service.
2. Register a username.
3. Use the identity point as the public key.
4. Start the collision challenge.
5. Send two different messages.
6. Send the fake signature.
7. The verifier accepts the same signature for both messages.

This is not a normal signature forgery against a real public key. It is more like abusing bad validation on public keys.

## Solution Script

Here is the final solve script.

```python
#!/usr/bin/env python3
import socket
import ssl
import sys
import time

HOST = "eddsa-dff5458057a0.c.mntcrl.it"
PORT = 443

IDENTITY = b"\x01" + b"\x00" * 31
PUBKEY_HEX = IDENTITY.hex()
SIG_HEX = (IDENTITY + b"\x00" * 32).hex()

MSG1 = "hello"
MSG2 = "world"
USERNAME = "ansh"

def recv_some(sock, timeout=0.4):
    sock.settimeout(timeout)
    out = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            out += chunk
            if b"> " in out or b": " in out or b"flag" in out.lower():
                break
        except TimeoutError:
            break
        except socket.timeout:
            break
    return out

def sendline(sock, s):
    sock.sendall(s.encode() + b"\n")
    time.sleep(0.1)

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT

    ctx = ssl._create_unverified_context()

    with ctx.wrap_socket(socket.create_connection((host, port)), server_hostname=host) as s:
        print(recv_some(s).decode(errors="ignore"), end="")

        sendline(s, "1")
        print(recv_some(s).decode(errors="ignore"), end="")

        sendline(s, USERNAME)
        print(recv_some(s).decode(errors="ignore"), end="")

        sendline(s, PUBKEY_HEX)
        print(recv_some(s).decode(errors="ignore"), end="")

        sendline(s, "3")
        print(recv_some(s).decode(errors="ignore"), end="")

        sendline(s, USERNAME)
        print(recv_some(s).decode(errors="ignore"), end="")

        sendline(s, MSG1)
        print(recv_some(s).decode(errors="ignore"), end="")

        sendline(s, MSG2)
        print(recv_some(s).decode(errors="ignore"), end="")

        sendline(s, SIG_HEX)

        time.sleep(0.5)
        final = recv_some(s, timeout=2)
        print(final.decode(errors="ignore"), end="")

if __name__ == "__main__":
    main()
```

Running it:

```bash
python3 solve.py
```

The important part is not the networking code. It is just these values:

```python
IDENTITY = b"\x01" + b"\x00" * 31
PUBKEY_HEX = IDENTITY.hex()
SIG_HEX = (IDENTITY + b"\x00" * 32).hex()
```

The public key is the identity point, and the signature is the identity point plus `S = 0`.

Because the verifier multiplies by the cofactor, the message hash term gets killed, so the same signature works for two different messages.

And that gives the flag.
