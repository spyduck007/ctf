---
title: A Strange Snake
date: 2026-06-28
tags:
- rev
- MntcrlCTF-2026
---

- **Challenge:** A Strange Snake
- **Category:** Rev
- **Flag:** `mntcrl{Th3_p3Rf3cT_C0upl3}`

---

## My initial read / first impressions

We are given a reversing challenge with the description:

```text
It could sseem easssier than it isss.
```

The wording is obviously weird. The repeated `s` letters and the name of the challenge both point toward some kind of snake / Python thing.

The file we get is:

- `rev-a-strange-snake.zip`

After unzipping it, the main thing inside is a Python bytecode file.

At first this seems like it should just be a normal `.pyc` reversing challenge. Usually that means using something like `pycdc`, `uncompyle6`, or just manually loading the code object and reading constants.

But the description already warns that it could seem easier than it is, and that ended up being pretty accurate.

## Looking at the pyc

The first thing I did was inspect the `.pyc`.

Running basic strings already showed that this was not really where the whole challenge lived. There was some lore-like text and then a huge encoded blob.

The Python bytecode was basically just a wrapper. It had a big “artifact” stored inside it, and the real goal was figuring out how to decode that artifact.

The important clue was in the text around the artifact. It hinted at:

```text
Base85
```

and also the value:

```text
0x40
```

So the idea was not to directly reverse the Python. The Python was just hiding another file.

The decoding logic was:

1. Take the big encoded blob.
2. Decode it as Base85.
3. XOR every byte with `0x40`.

After doing that, the output started with an ELF header:

```text
\x7fELF
```

So the “Python” challenge immediately turned into a normal native reversing challenge.

## Extracting the real binary

I wrote a small script to pull out the encoded blob from the `.pyc`, decode it, and write the ELF to disk.

```python
import base64
import marshal
import types

pyc = "snake.pyc"

with open(pyc, "rb") as f:
    f.read(16)
    code = marshal.load(f)

def walk(c):
    out = []
    for x in c.co_consts:
        if isinstance(x, types.CodeType):
            out += walk(x)
        else:
            out.append(x)
    return out

blob = None

for c in walk(code):
    if isinstance(c, str) and len(c) > 1000:
        blob = c.encode()
    if isinstance(c, bytes) and len(c) > 1000:
        blob = c

if blob is None:
    raise SystemExit("blob not found")

raw = base64.b85decode(blob)
elf = bytes(x ^ 0x40 for x in raw)

with open("snake_elf", "wb") as f:
    f.write(elf)
```

Then:

```bash
chmod +x snake_elf
file snake_elf
```

Output:

```text
snake_elf: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

So now the actual reversing target was this stripped ELF.

## Reversing the ELF

Since the binary was stripped, there were no helpful function names, but the logic was still pretty small.

The binary was basically asking for a password and validating it. The password was later used to unlock another zip file, so I just needed to recover the correct password.

There were two ways to approach it:

- reverse the password check statically in Ghidra
- use dynamic analysis and watch what it compares

I used Ghidra first to get the general structure.

The check was not just a plain string comparison, so `strings` did not instantly give the password. Instead, it was doing a small character-by-character validation with transformed values.

The important thing was that the password length was fixed. The binary expected a 14 character password.

Once I followed the validation logic, the characters came out as:

```text
Xk9mPqL2vRtN5w
```

So the native binary was not the final flag checker itself. It was a password oracle for the real final file.

## The zip layer

Inside the extracted challenge files, there was also a password protected zip:

```text
flag.zip
```

Using the recovered password:

```bash
unzip flag.zip
```

Password:

```text
Xk9mPqL2vRtN5w
```

That extracted the flag file.

```bash
cat flag.txt
```

Output:

```text
mntcrl{Th3_p3Rf3cT_C0upl3}
```

## Final solve script

This script does the full intended chain after the reversing part is known:

1. Extract the files from the challenge zip.
2. Find the `.pyc`.
3. Decode the hidden ELF from the bytecode.
4. Write the ELF to disk.
5. Use the recovered password to extract `flag.zip`.
6. Print the flag.

```python
import base64
import marshal
import os
import subprocess
import sys
import tempfile
import types
import zipfile

PASSWORD = "Xk9mPqL2vRtN5w"

def walk_code(code):
    values = []
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            values += walk_code(const)
        else:
            values.append(const)
    return values

def find_file(root, suffix):
    for path, dirs, files in os.walk(root):
        for name in files:
            if name.endswith(suffix):
                return os.path.join(path, name)
    return None

def extract_elf(pyc_path, out_path):
    with open(pyc_path, "rb") as f:
        f.read(16)
        code = marshal.load(f)

    blob = None

    for const in walk_code(code):
        if isinstance(const, str) and len(const) > 1000:
            blob = const.encode()
        if isinstance(const, bytes) and len(const) > 1000:
            blob = const

    if blob is None:
        raise RuntimeError("encoded blob not found")

    raw = base64.b85decode(blob)
    elf = bytes(x ^ 0x40 for x in raw)

    with open(out_path, "wb") as f:
        f.write(elf)

    os.chmod(out_path, 0o755)

def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} rev-a-strange-snake.zip")
        return 1

    challenge_zip = sys.argv[1]

    with tempfile.TemporaryDirectory() as tmp:
        with zipfile.ZipFile(challenge_zip) as z:
            z.extractall(tmp)

        pyc = find_file(tmp, ".pyc")
        flag_zip = find_file(tmp, "flag.zip")

        if pyc is None:
            print("pyc not found")
            return 1

        if flag_zip is None:
            print("flag.zip not found")
            return 1

        elf_path = os.path.join(tmp, "snake_elf")
        extract_elf(pyc, elf_path)

        out_dir = os.path.join(tmp, "out")
        os.mkdir(out_dir)

        subprocess.run(
            ["unzip", "-P", PASSWORD, flag_zip, "-d", out_dir],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        for path, dirs, files in os.walk(out_dir):
            for name in files:
                full = os.path.join(path, name)
                with open(full, "rb") as f:
                    data = f.read().decode(errors="ignore")
                if "mntcrl{" in data:
                    start = data.index("mntcrl{")
                    end = data.index("}", start) + 1
                    print(data[start:end])
                    return 0

        print("flag not found")
        return 1

if __name__ == "__main__":
    sys.exit(main())
```

Running it:

```bash
python solve.py rev-a-strange-snake.zip
```

Output:

```text
mntcrl{Th3_p3Rf3cT_C0upl3}
```

## Final thoughts

This challenge was a nice bait-and-switch.

At first it looks like a Python bytecode reversing challenge because of the `.pyc` file and the snake theme. But the `.pyc` is really just a container for a hidden ELF. The real challenge is noticing the Base85 + `0x40` decoding step, extracting the binary, and then reversing the password check inside that binary.

The final password was:

```text
Xk9mPqL2vRtN5w
```

Using that on `flag.zip` gives:

```text
mntcrl{Th3_p3Rf3cT_C0upl3}
```
