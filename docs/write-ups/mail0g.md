---
title: mail0g
date: 2026-06-28
tags:
- forensics
- MntcrlCTF-2026
---

* **Challenge:** mail0g
* **Category:** Forensics
* **Flag:** `mntcrl{I_c4n_s33333_y0ur_yah00_m41111111111!}`

---

## My initial read / first impressions

We are given a zip with one file inside:

- `mail.log`

The challenge description says:

```text
I noticed some suspicious logs suggesting someone was extracting information from the infrastructure. I’ve blocked a few things, but it might be better if you take a look as well.
```

So this immediately sounds like a log forensics challenge. The important words are “extracting information” and “blocked a few things”.

That made me think the flag was probably not directly written in the logs, but was being leaked through some normal-looking field. Since the file is a mail log, the suspicious data was probably hidden in email addresses, subjects, domains, or delivery metadata.

At first, the log looks super noisy. There are tons of normal mail delivery lines, cron authentications, DMARC stuff, TLS checks, and random external domains.

So the main goal was just finding what stood out.

## Looking through the logs

I started by grepping for obvious things like:

```bash
grep -i "mntcrl" mail.log
grep -i "yahoo" mail.log
grep -i "hotmail" mail.log
grep -i "zikko" mail.log
```

The user that stood out was:

```text
zikko@mntcrl.it
```

There were multiple outbound deliveries from this address to Yahoo and Hotmail addresses.

One example looked like this:

```text
from = "zikko@mntcrl.it", to = ["bl4nks4+6d6e7463@yahoo.com"]
```

That plus-tag is suspicious. `6d6e7463` is valid hex, and decoding it gives:

```text
mntc
```

Another one was:

```text
bl4nks4+726c7b@yahoo.com
```

Decoding `726c7b` gives:

```text
rl{
```

So the attacker was leaking the flag through email addresses.

## The Vulnerability

The “vulnerability” here is not a software exploit in the normal sense. It is data exfiltration through mail logs.

The attacker controlled parts of the recipient email address, specifically:

```text
local-part+tag@domain
```

For Yahoo, the data was mostly hidden in the plus-tag:

```text
bl4nks4+6d6e7463@yahoo.com
```

For Hotmail, some chunks were hidden directly in the mailbox name:

```text
333333335f79@hotmail.com
```

and sometimes both the mailbox and plus-tag were used:

```text
3075725f7961+6830305f6d343131@hotmail.com
```

Those hex chunks decode into pieces of the flag.

The trick is that the logs do not just show the final normalized recipient. They also preserve the original recipient address that the server attempted to deliver to. So even if the mail provider normalizes or ignores the plus-tag, the exfiltrated data is still sitting in the infrastructure logs.

## The Logic

The clean signal was:

- sender is `zikko@mntcrl.it`
- queue is `remote`
- message size is always `51823`
- recipients are Yahoo or Hotmail
- recipient local parts contain hex-looking strings
- queue IDs mostly increase in the same order as the flag chunks

The first few decoded chunks were:

```text
6d6e7463 -> mntc
726c7b -> rl{
495f6334 -> I_c4
6e5f7333 -> n_s3
```

Putting those together gives:

```text
mntcrl{I_c4n_s3
```

So from there it was just about collecting the rest of the chunks in the correct order.

Some of the later Hotmail chunks were slightly annoying because the suspicious local parts had odd-length hex strings. For example:

```text
31313131313@hotmail.com
```

Hex should have an even number of characters, but this is clearly a repeated `31`, which decodes to ASCII `1`.

So the intended chunk is basically:

```text
313131313131 -> 111111
```

There was also:

```text
13131217d@hotmail.com
```

This one makes sense if the missing leading nibble is restored:

```text
313131217d -> 111!}
```

That fits perfectly at the end of the flag.

So the “blocked a few things” part of the description was important. Some attempts were mangled or rejected, but the pattern was still obvious enough to reconstruct.

## Decoding the Exfil

The useful chunks in order were:

```text
6d6e7463                         -> mntc
726c7b                           -> rl{
495f6334                         -> I_c4
6e5f7333                         -> n_s3
333333335f79                     -> 3333_y
3075725f7961 + 6830305f6d343131 -> 0ur_yah00_m411
31313131313                      -> 111111
13131217d                        -> 111!}
```

Putting everything together:

```text
mntc
rl{
I_c4
n_s3
3333_y
0ur_yah00_m411
111111
111!}
```

Final flag:

```text
mntcrl{I_c4n_s33333_y0ur_yah00_m41111111111!}
```

## Solution Script

Here is the script I used to pull out the suspicious recipients, decode the hex chunks, and print the reconstructed flag.

```python
import re
import sys


def fix_hex(s):
    if len(s) % 2 == 0:
        return s

    if s.endswith("3"):
        return s + "1"

    if s.startswith("1"):
        return "3" + s

    return s


def decode_hex_piece(s):
    s = fix_hex(s)

    try:
        return bytes.fromhex(s).decode()
    except Exception:
        return ""


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} mail.log")
        return 1

    path = sys.argv[1]
    seen = set()
    chunks = []

    with open(path, "r", errors="ignore") as f:
        for line in f:
            if 'Message delivered' not in line:
                continue

            if 'from = "zikko@mntcrl.it"' not in line:
                continue

            match = re.search(r'queueId = (\d+).*?to = \["([^"]+)"\]', line)
            if not match:
                continue

            queue_id = int(match.group(1))
            addr = match.group(2)

            if (queue_id, addr) in seen:
                continue

            seen.add((queue_id, addr))

            local = addr.split("@")[0]
            parts = local.split("+")

            decoded = ""
            for part in parts:
                if re.fullmatch(r"[0-9a-fA-F]+", part):
                    decoded += decode_hex_piece(part)

            if decoded:
                chunks.append((queue_id, addr, decoded))

    chunks.sort()

    flag = ""
    for queue_id, addr, decoded in chunks:
        print(f"{queue_id} {addr} -> {decoded}")
        flag += decoded

    print()
    print(flag)


if __name__ == "__main__":
    sys.exit(main())
```

Running it:

```bash
python solve.py mail.log
```

Output:

```text
301782735486481791 bl4nks4+6d6e7463@yahoo.com -> mntc
307782735486481791 bl4nks4+726c7b@yahoo.com -> rl{
309782735486481791 bl4nks4+495f6334@yahoo.com -> I_c4
310782735486481791 bl4nks4+6e5f7333@yahoo.com -> n_s3
313782735486481791 333333335f79@hotmail.com -> 3333_y
314782735486481791 3075725f7961+6830305f6d343131@hotmail.com -> 0ur_yah00_m411
319782735486481791 31313131313@hotmail.com -> 111111
324782735486481791 13131217d@hotmail.com -> 111!}

mntcrl{I_c4n_s33333_y0ur_yah00_m41111111111!}
```

And that gives the flag.
