---
title: Motor City Search
date: 2026-11-20
tags:
- forensics
- WolvCTF-2026
---

- **Challenge:** Motor City Search
- **Category:** Forensics
- **Flag:** `wctf{Y0U_C4N_D0_1T_9d4427e73ff7}`

---

## My initial read / first impressions

The challenge description says:

```text
A seized logging rig captured a controller programming session. Its recovered log fragments were concatenated out of order. Reconstruct what was flashed to the controller and find the access token inside it.
```

We are given a tar.gz file. Extracting it gives one file, `capture.log`:

```bash
tar -xzf "dist (1).tar.gz"
wc -l capture.log
```

```text
4082 capture.log
```

The log is in the usual CAN dump format:

```text
(1730000001.010000) can0 7E8#027694AAAAAAAAAA
(1730000001.010227) can0 244#0BE5C97FCC7771C8
(1730000001.011000) can0 7E0#10123695C46E7DB3
```

So each line has a timestamp, the CAN interface, an arbitration ID, and the message bytes.

The description already tells us the logs are out of order, so reading them from top to bottom is going to be misleading. We need to sort by timestamp first, then figure out which messages actually belong to the firmware upload.

## Finding the programming traffic

There are a bunch of different CAN IDs mixed into the log, but `7E0` and `7E8` stood out. Those are the usual diagnostic request/response IDs for UDS over CAN.

The useful UDS services here are:

- `0x34` - RequestDownload, starts the firmware transfer
- `0x36` - TransferData, carries the actual bytes
- `0x37` - RequestTransferExit, finishes the transfer

The messages also use ISO-TP, so one UDS message can be spread over multiple CAN frames. For example, after sorting, the start of the second download looks like:

```text
(1730000000.263000) can0 7E0#100B341044004000
(1730000000.264000) can0 7E8#300000AAAAAAAAAA
(1730000000.265000) can0 7E0#210000001F4CAAAA
(1730000000.266000) can0 7E8#0474200012AAAAAA
(1730000000.267000) can0 7E0#1012360178DA9578
```

The `10` byte marks an ISO-TP first frame, `21` is a consecutive frame, and `30` is flow control. Once those transport bytes are stripped, the UDS payload starts with `34` or `36`.

That last line is especially useful:

```text
36 01 78 DA 95 78 ...
```

`36` is TransferData, `01` is the block counter, and `78 DA` looks like the beginning of a zlib stream. So the firmware was probably compressed before being sent.

## The failed download and the duplicate block

There are actually two RequestDownload messages in the sorted log. The first starts at timestamp `1730000000.108000`, and the second starts at `1730000000.263000`.

The first attempt fails with:

```text
7E8#037F3671AAAAAAAA
```

That is a negative UDS response to TransferData (`7F 36 71`). If we mix the blocks from both attempts, the resulting data is going to be wrong. I ignored everything before the second RequestDownload and reconstructed that session.

There was one more annoying detail: block counter `0x2e` was sent twice with the exact same contents. It was a retransmission, not another piece of the firmware. Keeping both copies breaks the compressed stream, so I skipped the duplicate.

After that, the block counters go in order and we get 496 unique TransferData blocks.

## Reconstructing the firmware

I used Python for this because there are over 4,000 log lines, and manually rebuilding ISO-TP packets would be miserable.

The script sorts the frames, starts at the second download, joins the consecutive ISO-TP frames for each `0x36` message, and removes the repeated block. Then it decompresses the data and looks for the embedded ZIP.

## Solution script

```python
#!/usr/bin/env python3
import io
import re
import sys
import tarfile
import zipfile
import zlib
from decimal import Decimal
from pathlib import Path


archive = sys.argv[1] if len(sys.argv) > 1 else "dist (1).tar.gz"

with tarfile.open(archive, "r:gz") as tar:
    lines = tar.extractfile("capture.log").read().decode().splitlines()

frames = []
for line in lines:
    m = re.fullmatch(r"\((\d+\.\d+)\) can0 ([0-9A-F]+)#([0-9A-F]+)", line)
    if m:
        frames.append((Decimal(m[1]), m[2], bytes.fromhex(m[3])))

frames.sort()

# There are two downloads. The first one fails.
downloads = [
    t for t, can_id, data in frames
    if can_id == "7E0" and data.startswith(b"\x10\x0b\x34")
]
start = downloads[-1]

blocks = []
for i, (t, can_id, data) in enumerate(frames):
    if t <= start or can_id != "7E0":
        continue
    if data[:3] not in (b"\x10\x12\x36", b"\x10\x0d\x36"):
        continue

    length = ((data[0] & 0x0f) << 8) | data[1]
    packet = bytearray(data[2:])
    seq = 0x21

    for _, next_id, next_data in frames[i + 1:]:
        if next_id == "7E0" and next_data and next_data[0] == seq:
            packet.extend(next_data[1:])
            seq += 1
            if len(packet) >= length:
                break

    packet = bytes(packet[:length])
    assert len(packet) == length and packet[0] == 0x36
    block = (packet[1], packet[2:])

    # Block 0x2e gets retransmitted unchanged.
    if blocks and blocks[-1] == block:
        continue
    blocks.append(block)

assert len(blocks) == 496
assert all(counter == (i + 1) % 256 for i, (counter, _) in enumerate(blocks))

compressed = b"".join(data for _, data in blocks)
firmware = zlib.decompress(compressed)

assert len(firmware) == 8012
assert zlib.crc32(firmware) == 0x170fb8e9

Path("motor_city_firmware.bin").write_bytes(firmware)

zip_offset = firmware.index(b"PK\x03\x04")
with zipfile.ZipFile(io.BytesIO(firmware[zip_offset:])) as zf:
    token = zf.read("immo_key.bin")

Path("immo_key.bin").write_bytes(token)
print(token.decode())
```

Running it:

```bash
python3 solve.py "dist (1).tar.gz"
```

```text
wctf{Y0U_C4N_D0_1T_9d4427e73ff7}
```

## Checking the recovered image

The transfer data adds up to 7,931 compressed bytes. Decompressing it gives an 8,012-byte firmware image with this header:

```text
WOLVSEC IMMO BOOTLOADER v3 :: image continues past this header; keep reconstructing ::
```

The CRC32 is `0x170fb8e9`, which matches the checksum in the programming session, so the recovered firmware is not missing any blocks.

Searching for `PK\x03\x04` finds a ZIP header at offset `4856`. Inside that ZIP is a single file:

```text
immo_key.bin
```

Reading it gives the access token. The main issue was getting the order right and not accidentally including data from the failed transfer or the repeated `0x2e` block.

## Final flag

```text
wctf{Y0U_C4N_D0_1T_9d4427e73ff7}
```
