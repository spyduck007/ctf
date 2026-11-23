---
title: XOR OS
date: 2026-11-20
tags:
- crypto
- WolvCTF-2026
---

- **Challenge:** XOR OS
- **Category:** Crypto
- **Flag:** `wctf{Som3_Tim3_p4D}`

---

## My initial read / first impressions

The challenge description says:

```text
We found this disk image just lying around. Unfortunately, the unlock key wasn't included.
```

We're given a disk image called `chal.bin`. Running `file` identifies it as a DOS/MBR boot sector:

```bash
file chal.bin
xxd -l 96 chal.bin
```

The start of the image is a little weird. It has a QEMU command written right into it:

```text
qemu-system-x86_64 $0 -boot c -device loader,file=key.bin,addr=0x100000
echo did ya solve it yet?
exit
```

So the missing key is literally a file called `key.bin`, which QEMU is supposed to load at `0x100000`. After the first 512 bytes, the disk is mostly random-looking data. There aren't any useful flag strings sitting in plaintext.

## Finding the XOR period

The first 512 bytes are the boot sector, so I worked with everything after that. Since this is called XOR OS, I started checking whether the encrypted bytes repeated with some fixed offset.

There was a big spike at `0xC0DE`, or 49,374 bytes. Comparing the first 200,000 ciphertext bytes against the same bytes shifted by different amounts gave:

```text
Shift       Matching bytes
0xc0dd      0.40%
0xc0de      5.56%
0xc0df      0.39%
```

Normally two unrelated random-looking byte streams match about 1/256 of the time, around 0.39%. The much higher match rate at `0xC0DE` means the same XOR pad is probably being reused at that distance.

## Recovering the key

The ciphertext is a little over 5 MB, so a 49,374-byte pad gets reused about 101 times. That gives us around 101 ciphertext bytes encrypted with the same key byte at each position.

The useful part is that the original data has a lot of zero bytes. Since `0 ^ key_byte = key_byte`, the most common ciphertext value in each column is a good guess for that key byte.

In Python, the key recovery is basically:

```python
from collections import Counter

period = 0xC0DE
key = bytes(
    Counter(ciphertext[i::period]).most_common(1)[0][0]
    for i in range(period)
)
```

Then XOR every ciphertext byte with its corresponding position in the recovered pad:

```python
decrypted = bytes(b ^ key[i % period] for i, b in enumerate(ciphertext))
```

That gave me something that actually looks like x86 code, starting with `8d 4c 24 04 83 e4 f0 ff`. The decrypted data also contains a long ASCII-art string.

## Reading the flag

The decrypted program uses a pointer stored at offset `0xD8`. It's `0x2000e0`, and the payload is loaded at `0x200000`, so the string starts at offset `0xE0` inside the decrypted file.

The program prints the string to the VGA text buffer at a width of 77 characters. If you print the string as one long line, it looks like garbage. Splitting it into rows of 77 gives the actual banner.

The top spells out `wctf{`, and the rest spells out `Som3_Tim3_p4D}`. The underscores and capitalization were easy to misread in the ASCII art, so I checked those separately before submitting the flag.

## Solution script

This reads `chal.bin`, recovers the XOR pad, writes out the decrypted payload, and prints the banner at the right width.

```python
#!/usr/bin/env python3
from collections import Counter
from pathlib import Path

image = Path("chal.bin").read_bytes()
ciphertext = image[512:]
period = 0xC0DE

key = bytes(
    Counter(ciphertext[i::period]).most_common(1)[0][0]
    for i in range(period)
)
decrypted = bytes(b ^ key[i % period] for i, b in enumerate(ciphertext))

# The loader expects a two-byte length before the pad.
Path("key.bin").write_bytes((period + 2).to_bytes(2, "little") + key)
Path("decrypted_payload.bin").write_bytes(decrypted)

start = int.from_bytes(decrypted[0xD8:0xDC], "little") - 0x200000
end = decrypted.index(0, start)
banner = decrypted[start:end].decode("ascii")

for i in range(0, len(banner), 77):
    print(banner[i:i + 77].rstrip())
```

Run it from the directory with `chal.bin`:

```bash
python3 solve.py
```

The banner comes out like this:

```text
              _    __   __
__      _____| |_ / _| / /
\ \ /\ / / __| __| |_ | |
 \ V  V / (__| |_|  _< <
  \_/\_/ \___|\__|_|  | |
 ____                  \_\__  _____ _           _____           _  _   ____
/ ___|  ___  _ __ ___ |___ / |_   _(_)_ __ ___ |___ /     _ __ | || | |  _ \
\___ \ / _ \| '_ ` _ \  |_ \   | | | | '_ ` _ \  |_ \    | '_ \| || |_| | | |
 ___) | (_) | | | | | |___) |  | | | | | | | | |___) |   | |_) |__   _| |_| |
|____/ \___/|_| |_| |_|____/___|_| |_|_| |_| |_|____/____| .__/   |_| |____/
\ \                       |_____|                  |_____|_|
 | |
  > >
 | |
/_/
```

## Why this works

The key is supposed to be missing, but the same XOR pad was used over and over across the disk. Because the decrypted program has so many zero bytes, every position in the pad can be estimated by taking the most common ciphertext byte at that position across all the repeats.

Once the pad is recovered, the rest is regular XOR decryption. The flag was in the decrypted program the whole time, just drawn as ASCII art instead of stored as a normal `wctf{...}` string.

## Final flag

```text
wctf{Som3_Tim3_p4D}
```
