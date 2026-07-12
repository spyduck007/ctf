---
title: Mirror Mirror
date: 2026-07-11
tags:
- rev
- BroncoCTF-2026
---

- **Challenge:** Mirror Mirror
- **Category:** Rev
- **Flag:** `bronco{wh0_1s_th3_f@ir3st_r3v3rs3r}`

---

## My initial read / first impressions

The challenge description says:

```text
I've been told that this magic mirror will only clear when I give it the flag. Can you help me figure out what I should say?
```

We are given a Python file called `mirror.py`. Running it normally just asks for a password:

```text
Enter the password to gaze into the mirror:
```

At first this looks like a normal password checker, but the source makes it pretty clear that the program is trying to be a little annoying instead of just storing the flag directly.

The important function is `verify(attempt)`. It does three main things:

1. Reads its own source file through `__file__`.
2. Hashes a 300-character slice starting at the string `MIRROR_SURFACE_DO_NOT_SCRATCH`.
3. Uses that hash, the string `MirrorMirror`, and a hardcoded `blob` array to rebuild the real flag.

So the flag is not really hidden in a complicated way. The script already contains everything needed to recover it. The only trick is that the final string is generated dynamically from the file contents.

## The anti-debug / anti-import checks

Before the script checks the password, it has a few small traps:

```python
if sys.gettrace() is not None:
    return "Nice try, but the glass turns opaque. No observers allowed!"
if sys._getframe().f_code.co_name != 'verify' or __name__ != "__main__":
    return "You are looking at the mirror from a distorted angle."
```

The first one blocks normal debugger tracing. The second one makes sure the function is actually called as `verify` while the file is running as `__main__`.

This means importing the file and calling `verify()` from another script is not the cleanest path, because `__name__` would not be `"__main__"`. But we do not really need to call `verify()` at all.

The decode logic is sitting right there, so I just copied the same operations into a small solve script.

## Rebuilding the mirror map

The first important piece is this part:

```python
with open(__file__, 'r') as f:
    src = f.read()
    pivot = src.index("MIRROR_SURFACE_DO_NOT_SCRATCH")
    specular_map = hashlib.sha256(src[pivot:pivot+300].encode()).digest()
```

The script hashes a slice of its own source code. That means the exact contents of the file matter. If I accidentally edited the source, added a newline, or copied only part of the file into another script, the hash could change and the output would be garbage.

So the solve script should read the original `mirror.py` file and compute the same `specular_map` from it.

After that, the rest is just XOR.

The hardcoded data is:

```python
blob = [17, 241, 10, 247, 215, 233, 146, 221, 156, 40, 37, 198, 153, 173, 10, 103, 20, 56, 232, 116, 208, 121, 53, 12, 122, 86, 127, 164, 109, 62, 88, 200, 127, 234, 5]
```

and the repeating key is:

```python
looking_glass = "MirrorMirror"
```

For every byte, the script computes:

```text
reflection_byte = specular_map[i % len(specular_map)] ^ looking_glass[i % len(looking_glass)]
flag_byte       = blob[i] ^ reflection_byte
```

So we can directly reverse the flag by running that same loop.

## Solution script

This is the script I used:

```python
#!/usr/bin/env python3
from pathlib import Path
import hashlib

src = Path("mirror.py").read_text()

pivot = src.index("MIRROR_SURFACE_DO_NOT_SCRATCH")
specular_map = hashlib.sha256(src[pivot:pivot + 300].encode()).digest()

blob = [
    17, 241, 10, 247, 215, 233, 146, 221, 156, 40, 37, 198,
    153, 173, 10, 103, 20, 56, 232, 116, 208, 121, 53, 12,
    122, 86, 127, 164, 109, 62, 88, 200, 127, 234, 5,
]

looking_glass = "MirrorMirror"
flag = ""

for i, b in enumerate(blob):
    reflection_byte = specular_map[i % len(specular_map)] ^ ord(looking_glass[i % len(looking_glass)])
    flag += chr(b ^ reflection_byte)

print(flag)
```

Running it prints:

```text
bronco{wh0_1s_th3_f@ir3st_r3v3rs3r}
```

## Why this works

The challenge is basically self-referential XOR obfuscation.

The file computes a SHA-256 hash from its own source code, uses that hash as part of a repeating XOR stream, and then XORs that stream against a hardcoded list of bytes. Since the source code, the `blob`, and the key string are all available to us, we can reproduce the exact same process outside the password checker.

The anti-debug and anti-import checks make the obvious dynamic approach slightly annoying, but they do not protect the actual secret because the transformation is fully visible in the source.

The full chain is:

```text
read mirror.py
    -> find MIRROR_SURFACE_DO_NOT_SCRATCH
    -> hash 300 characters from that point
    -> combine hash with "MirrorMirror"
    -> XOR against blob
    -> recover flag
```

## Flag

```text
bronco{wh0_1s_th3_f@ir3st_r3v3rs3r}
```
