---
title: In Jeopardy!
date: 2026-11-20
tags:
- rev
- WolvCTF-2026
---

- **Challenge:** In Jeopardy!
- **Category:** Rev
- **Flag:** `wctf{Ch411Eng35-f0R_tW0-HUNDR3D}`

---

## My initial read / first impressions

The challenge description says:

```text
Welcome to Jeopardy! Run the executable to see what your first question is. Don't know the answer? Then you might have some digging to do...
```

We get `dis (2).tar.gz` with one executable inside:

```bash
tar -xzf "dis (2).tar.gz"
file in-jeopardy
```

```text
in-jeopardy: ELF 64-bit LSB executable, x86-64, statically linked, for GNU/Linux 3.2.0, with debug_info, not stripped
```

Running it doesn't give us a normal trivia question. Instead, it prints this:

```text
This password is used to gain the flag from the user in the Jeopardy Rev challenge.
```

If I type something random, it tells me to start with `What is`. So the clue is asking for a password in Jeopardy answer format. Rather than guess a bunch of phrases, I checked the binary.

## Finding the right answer

The binary isn't stripped, so the useful function names are still there. `main()` calls `key()` and compares our input against the string `What is ` followed by whatever `key()` returns.

```bash
objdump -d -C -M intel --start-address=0x404a55 --stop-address=0x404e36 in-jeopardy
```

At `0x404a55`, `key()` builds a string one character at a time. The characters are `t`, `h`, `e`, a space, `f`, `l`, `a`, `g`, `?`, and `!`.

So `key()` returns:

```text
the flag?!
```

And the full input that `main()` wants is:

```text
What is the flag?!
```

When that comparison succeeds, `main()` calls `print_key_message()` at `0x404b3e`.

## Decoding the flag

Inside `print_key_message()`, there's a string loaded from `.rodata` at `0x55a008`. It doesn't look like a flag at first:

```python
b'zfwi~Fk744Hqj680i3UbwZ30KXQGU6G\x80'
```

The decoding loop is pretty small. For each byte, the program subtracts `3` and appends the result to a new string. You can see the subtraction at `0x404be1`:

```asm
404bdd: movzx eax, BYTE PTR [rbp-0x19]
404be1: sub   eax, 0x3
```

So it's a Caesar shift on the raw bytes. Subtracting 3 from the encoded data gives `wctf{Ch411Eng35-f0R_tW0-HUNDR3D}`. The last byte is `0x80`, which becomes `}` after the subtraction.

## Solution script

This reads the encoded bytes straight from the executable and decodes them. No need to run the binary or type the answer once we know where the string is.

```python
#!/usr/bin/env python3
from pathlib import Path

data = Path("in-jeopardy").read_bytes()
start = data.index(b"zfwi~")
encoded = data[start:start + 32]

flag = bytes((b - 3) % 256 for b in encoded)
print(flag.decode())
```

```bash
python3 solve.py
```

```text
wctf{Ch411Eng35-f0R_tW0-HUNDR3D}
```

I also checked it by giving the executable the answer directly:

```bash
printf 'What is the flag?!\n' | ./in-jeopardy
```

```text
This password is used to gain the flag from the user in the Jeopardy Rev challenge.
Correct! 
wctf{Ch411Eng35-f0R_tW0-HUNDR3D}
```

## Why this works

The Jeopardy part is just an exact string comparison. `key()` hides the rest of the expected answer by adding the characters individually, and the flag is stored separately with every byte shifted up by 3. Reading those bytes and undoing the shift skips the input check entirely.

## Final flag

```text
wctf{Ch411Eng35-f0R_tW0-HUNDR3D}
```
