---
title: obscure-crusher-2
date: 2026-05-17
tags:
- forensics
- TJCTF-2026
---

- **Challenge:** obscure-crusher-2
- **Category:** Forensics
- **Flag:** `tjctf{polygl0t_m3tadata_1s_th3_k3y}`

---

## My initial read / first impressions

We are given one file:

```text
chall.icns
```

and the challenge description says:

```text
What if the key isn’t something you find...
but something you build?
```

So right away, this does not feel like a normal “run strings and find the flag” challenge. The file extension is `.icns`, which is Apple’s icon format, but the description makes it sound like the flag is not directly hidden somewhere. Instead, some pieces of the file probably have to be combined to build a key.

Opening the file in a hex editor shows that it starts like a normal ICNS-style file:

```text
69 63 6e 73
```

which is:

```text
icns
```

ICNS files are chunk-based. The rough structure is:

```text
magic:  4 bytes
size:   4 bytes, big endian

then repeated chunks:
type:   4 bytes
size:   4 bytes, big endian
data:   size - 8 bytes
```

That already matches the challenge description pretty well. If the file is made of chunks, then the “key” might come from metadata about those chunks instead of the raw contents.

## Parsing the ICNS chunks

The first thing I did was write a small parser for the ICNS container. The important part is that the lengths are big endian, not little endian:

```python
def parse_icns(blob):
    if blob[:4] != b"icns":
        raise ValueError("not an ICNS-like file")

    total = struct.unpack_from(">I", blob, 4)[0]

    chunks = []
    p = 8

    while p + 8 <= total:
        typ = blob[p:p + 4]
        length = struct.unpack_from(">I", blob, p + 4)[0]

        payload = blob[p + 8:p + length]
        chunks.append((typ, payload, p, length))

        p += length

    return chunks
```

Dumping the chunk types gives something like:

```text
TOC 
ic09
ic07
ic13
ic11
ttf 
lzM4
```

The `TOC ` chunk is basically screaming at us:

```text
metadata/orders/checksums
```

That is a pretty good hint for what matters:

```text
metadata
order
checksums
```

So the actual icon image data is probably not the important thing by itself. The important thing is the metadata around the icon chunks: their type, length, and checksum.

## The icon chunk material

There are four normal-looking icon chunks:

```text
ic07
ic09
ic11
ic13
```

They start with PNG magic bytes, but they are not really there to be opened as useful images. They are there to contribute to the key.

The material from the icon chunks is built like this:

```python
def icns_material(chunks):
    interesting = {
        b"ic07",
        b"ic09",
        b"ic11",
        b"ic13",
    }

    icon_chunks = []

    for typ, payload, off, length in chunks:
        if typ in interesting:
            icon_chunks.append((typ, payload))

    h = hashlib.sha256()

    for typ, payload in sorted(icon_chunks, key=lambda x: x[0]):
        h.update(typ)
        h.update(struct.pack(">I", 8 + len(payload)))
        h.update(struct.pack(">I", zlib.crc32(payload) & 0xFFFFFFFF))

    return h.digest()
```

There are a few easy places to mess this up:

```text
the chunks have to be sorted by type
the length includes the 8-byte chunk header
the CRC is over the payload only
the length and CRC are packed big endian
```

This is also where the challenge starts feeling less like “extract the hidden file” and more like “reconstruct the author’s exact key schedule.”

## The embedded TTF

The next suspicious chunk is:

```text
ttf 
```

This contains a tiny TrueType font.

A TTF file is also table-based. At the start, it has an offset table and then a table directory. One of those tables is the `name` table, which stores font names like the family name, style, full name, and so on.

Parsing the TTF table directory shows a few tables:

```text
head
maxp
name
```

The normal names are boring:

```text
Crush Sans
Regular
Crush Sans Regular
CrushSans-Regular
```

But the custom name records are much more interesting:

```text
north-facing-icons
tables-before-strings
lengths-are-big-endian
names-sort-by-id
```

These are basically mini-hints hidden in the font metadata.

The solve only cares about name records where:

```text
name_id >= 0x0100
```

Those records are sorted and hashed into the key material.

```python
def ttf_material(ttf):
    sfnt, num_tables = struct.unpack_from(">IH", ttf, 0)

    if sfnt != 0x00010000:
        raise ValueError("embedded TTF has wrong sfnt version")

    name_off = None
    p = 12

    for i in range(num_tables):
        tag = ttf[p:p + 4]
        checksum_value, off, length = struct.unpack_from(">III", ttf, p + 4)

        if tag == b"name":
            name_off = off

        p += 16

    if name_off is None:
        raise ValueError("embedded TTF has no name table")

    fmt, count, string_offset = struct.unpack_from(">HHH", ttf, name_off)

    string_base = name_off + string_offset
    record_pos = name_off + 6
    records = []

    for i in range(count):
        platform, encoding, language, name_id, length, off = struct.unpack_from(
            ">HHHHHH",
            ttf,
            record_pos,
        )

        raw = ttf[string_base + off:string_base + off + length]

        if name_id >= 0x0100:
            records.append((name_id, platform, encoding, language, raw))

        record_pos += 12

    h = hashlib.sha256()

    for name_id, platform, encoding, language, raw in sorted(records):
        h.update(struct.pack(">HHHHH", name_id, platform, encoding, language, len(raw)))
        h.update(raw)

    return h.digest()
```

Again, there are some annoying details that matter:

```text
the TTF directory comes before the table data
the name strings are stored after the name records
the strings use their own offset relative to the name table string area
the custom name records need to be sorted
the raw bytes should be hashed, not the decoded strings
```

That last point is especially important because some records are UTF-16-BE. If you decode and re-encode them slightly wrong, the hash changes and the final CRC check fails.

## The LZMA chunk

The final suspicious chunk is:

```text
lzM4
```

The payload starts with:

```text
5d 00 00 80 00
```

Those are LZMA-Alone properties.

The challenge also uses those exact 5 bytes as part of the key derivation, so they are not just a decompression detail. The key is built from:

```text
"CRUSHER2|"
+ icon metadata hash
+ TTF metadata hash
+ LZMA properties
```

In code:

```python
LZMA_PROPS = bytes.fromhex("5d00008000")

def derive_key(chunks, ttf):
    data = (
        b"CRUSHER2|"
        + icns_material(chunks)
        + ttf_material(ttf)
        + LZMA_PROPS
    )

    return hashlib.sha256(data).digest()
```

At this point, we can decompress the LZMA payload:

```python
inner = lzma.decompress(lzma_payload, format=lzma.FORMAT_ALONE)
```

The decompressed payload starts with:

```text
CRUSHER2
```

Then it has a small header:

```text
magic:      8 bytes
version:    uint16 big endian
flag_len:   uint8
crc:        uint32 big endian
ciphertext: flag_len bytes
```

So the LZMA chunk does not directly contain the flag. It contains an encrypted flag and enough information to check whether the derived key was right.

## Decrypting the flag

The encryption is a simple SHA-256 based XOR stream.

For each block:

```text
sha256(key || counter)
```

where the counter is a big endian 32-bit integer.

Then XOR the stream with the ciphertext:

```python
def stream_xor(data, key):
    stream = bytearray()
    counter = 0

    while len(stream) < len(data):
        block = hashlib.sha256(key + struct.pack(">I", counter)).digest()
        stream.extend(block)
        counter += 1

    return bytes(a ^ b for a, b in zip(data, stream))
```

After decrypting, the CRC from the inner payload confirms whether everything was parsed correctly.

If the key is even slightly wrong, the CRC does not match. This made the challenge pretty unforgiving, because missing one endian swap or sorting detail completely breaks the solve.

## Final Solve

Here is the full solve script:

```python
import sys
import struct
import hashlib
import zlib
import lzma

LZMA_PROPS = bytes.fromhex("5d00008000")


def u32(x):
    return struct.pack(">I", x)


def parse_icns(blob):
    if blob[:4] != b"icns":
        raise ValueError("not an ICNS-like file")

    total = struct.unpack_from(">I", blob, 4)[0]

    if total > len(blob):
        raise ValueError("truncated ICNS file")

    chunks = []
    p = 8

    while p + 8 <= total:
        typ = blob[p:p + 4]
        length = struct.unpack_from(">I", blob, p + 4)[0]

        if length < 8:
            raise ValueError("bad chunk length at offset " + str(p))

        if p + length > total:
            raise ValueError("chunk at offset " + str(p) + " exceeds ICNS length")

        payload = blob[p + 8:p + length]
        chunks.append((typ, payload, p, length))

        p += length

    return chunks


def icns_material(chunks):
    interesting = {
        b"ic07",
        b"ic09",
        b"ic11",
        b"ic13",
    }

    icon_chunks = []

    for typ, payload, off, length in chunks:
        if typ in interesting:
            icon_chunks.append((typ, payload))

    h = hashlib.sha256()

    for typ, payload in sorted(icon_chunks, key=lambda x: x[0]):
        h.update(typ)
        h.update(u32(8 + len(payload)))
        h.update(u32(zlib.crc32(payload) & 0xFFFFFFFF))

    return h.digest()


def ttf_material(ttf):
    sfnt, num_tables = struct.unpack_from(">IH", ttf, 0)

    if sfnt != 0x00010000:
        raise ValueError("embedded TTF has wrong sfnt version")

    name_off = None
    p = 12

    for i in range(num_tables):
        tag = ttf[p:p + 4]
        checksum_value, off, length = struct.unpack_from(">III", ttf, p + 4)

        if tag == b"name":
            name_off = off

        p += 16

    if name_off is None:
        raise ValueError("embedded TTF has no name table")

    fmt, count, string_offset = struct.unpack_from(">HHH", ttf, name_off)

    string_base = name_off + string_offset
    record_pos = name_off + 6
    records = []

    for i in range(count):
        platform, encoding, language, name_id, length, off = struct.unpack_from(
            ">HHHHHH",
            ttf,
            record_pos,
        )

        raw = ttf[string_base + off:string_base + off + length]

        if name_id >= 0x0100:
            records.append((name_id, platform, encoding, language, raw))

        record_pos += 12

    h = hashlib.sha256()

    for name_id, platform, encoding, language, raw in sorted(records):
        packed = struct.pack(">HHHHH", name_id, platform, encoding, language, len(raw))
        h.update(packed)
        h.update(raw)

    return h.digest()


def derive_key(chunks, ttf):
    data = b"CRUSHER2|" + icns_material(chunks) + ttf_material(ttf) + LZMA_PROPS
    return hashlib.sha256(data).digest()


def stream_xor(data, key):
    stream = bytearray()
    counter = 0

    while len(stream) < len(data):
        block = hashlib.sha256(key + struct.pack(">I", counter)).digest()
        stream.extend(block)
        counter += 1

    return bytes(a ^ b for a, b in zip(data, stream))


def main(path):
    with open(path, "rb") as f:
        blob = f.read()

    chunks = parse_icns(blob)

    ttf_payload = None
    lzma_payload = None

    for typ, payload, off, length in chunks:
        if typ == b"ttf ":
            ttf_payload = payload
        elif typ == b"lzM4":
            lzma_payload = payload

    if ttf_payload is None:
        raise ValueError("missing embedded TTF chunk")

    if lzma_payload is None:
        raise ValueError("missing embedded LZMA chunk")

    if lzma_payload[:5] != LZMA_PROPS:
        raise ValueError("unexpected LZMA properties")

    key = derive_key(chunks, ttf_payload)

    inner = lzma.decompress(lzma_payload, format=lzma.FORMAT_ALONE)

    if inner[:8] != b"CRUSHER2":
        raise ValueError("bad inner payload magic")

    version, flag_len, expected_crc = struct.unpack_from(">HBI", inner, 8)

    if version != 2:
        raise ValueError("unexpected payload version")

    ciphertext = inner[15:15 + flag_len]

    flag = stream_xor(ciphertext, key)

    actual_crc = zlib.crc32(flag) & 0xFFFFFFFF

    if actual_crc != expected_crc:
        raise ValueError("wrong key or corrupted file")

    print(flag.decode())


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "chall.icns"

    main(target)
```

Running it:

```bash
python3 solve.py chall.icns
```

prints:

```text
tjctf{polygl0t_m3tadata_1s_th3_k3y}
```

## Final Thoughts

I think the main trap in this challenge is that the flag is not hidden in one place. There is no single “important” chunk that you can extract and be done with.

The file is basically a small polyglot puzzle:

```text
ICNS chunk metadata
+ fake icon payload checksums
+ TTF name table metadata
+ LZMA properties
= decryption key
```

The `TOC ` chunk and the weird font names are the main breadcrumbs, but the solve still depends on matching the exact parsing rules of both formats. Sort order, endian-ness, raw string bytes, chunk sizes, and checksums all matter.

So the real lesson is probably:

```text
do not just look inside the file
look at how the file is put together
```

The final flag was:

```text
tjctf{polygl0t_m3tadata_1s_th3_k3y}
```

And if another Crusher ever shows up, I am definitely not trusting the file extension first.
