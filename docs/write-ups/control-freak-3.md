---
title: Control Freak 3
date: 2026-07-06
tags:
- rev
- LYKNCTF
---

- **Challenge:** Control Freak 3
- **Category:** Rev
- **Flag:** `LYKNCTF{0UT_0F_C0NTR0L_VM2026}`

---

## My initial read / first impressions

The challenge name is **Control Freak 3**, and the description is just:

```text
Control Again!!!
```

We are given two binaries:

```text
chall-4
chall-4.exe
```

So this already sounded like another control-flow / anti-debug reversing challenge. Since we had both a Linux and Windows build, I focused on the Linux binary first because it is easier to patch and test locally.

Running the binary just asks for the flag:

```text
flag:
```

A wrong input gives the normal wrong-answer output, and the real flag is not sitting in `strings`, so this was not going to be a basic hardcoded string compare.

## Finding the checker

Looking through the disassembly, the binary does a few suspicious things before it ever reaches the actual flag check.

The important shape is:

```text
anti-debug / environment checks
    -> build some state value
    -> decrypt small bytecode chunks from .rodata
    -> run a custom VM over the input
    -> accept only if the VM error accumulator is still zero
```

There were five encrypted chunks in `.rodata`, and the binary decrypts them before interpreting them. So the actual checker is hidden behind a tiny virtual machine instead of normal compare instructions.

At this point, the obvious plan would be to reverse the VM instruction set and recover the constraints. But there was another issue first: the program intentionally messes with the state depending on whether its anti-debug checks fire.

## The anti-debug part

The binary checks for a bunch of debugging / instrumentation signs, including:

```text
/proc/self/status / TracerPid
SIGTRAP behavior
LD_PRELOAD / LD_AUDIT
/proc/self/maps strings like frida, gdb, lldb, pin, qemu
ptrace(PTRACE_TRACEME)
```

Most of these checks are annoying but not too surprising for this kind of challenge. The part that mattered was the `SIGTRAP` path.

There is a block that looks like this:

```asm
401373: xor eax, 0x5be0cd19
40137d: mov edx, 0x67
401382: cmove r15d, eax
```

This is the main sabotage. When the trap handler behaves the way the program expects, this conditionally moves the XORed value into `r15d`. Later, the VM mixes this value into the final accumulator.

So the annoying part is that the anti-debug logic is not just there to detect debugging. It becomes part of the flag check. If this value is poisoned, the VM can end with a bad accumulator even if the flag constraints are otherwise correct.

In other words, the program is basically saying:

```text
correct flag constraints
AND
anti-debug state is clean
```

If the anti-debug state is wrong, the answer never reaches the clean success path.

## Patching the poison

Instead of fighting all of the anti-debug checks one by one, I patched out the instruction that poisons `r15d`.

The instruction is at:

```text
virtual address: 0x401382
file offset:     0x1382
```

I replaced the `cmove r15d, eax` instruction with NOPs:

```bash
cp chall-4 chall-4.patch
python3 - <<'PY'
from pathlib import Path

p = Path("chall-4.patch")
b = bytearray(p.read_bytes())

# Patch cmove r15d, eax at file offset 0x1382.
b[0x1382:0x1386] = b"\x90" * 4

p.write_bytes(b)
PY
chmod +x chall-4.patch
```

This patch does not skip the actual flag checker. It only prevents the anti-debug state from poisoning the VM result.

That made the rest of the reversing a lot cleaner, because now the binary's success/fail output actually corresponded to the VM constraints instead of also depending on the trap state.

## Recovering the flag

After that, the VM logic was much more straightforward to reason about. The decrypted program checks the input bytes and accumulates an error value. The success condition is that the accumulator stays zero by the end.

The recovered flag was:

```text
LYKNCTF{0UT_0F_C0NTR0L_VM2026}
```

To confirm it, I ran the patched binary with that input:

```bash
printf 'LYKNCTF{0UT_0F_C0NTR0L_VM2026}\n' | ./chall-4.patch
```

and got:

```text
flag: Correct!
```

## Why this works

The challenge tries to make the actual control flow hard to trust in two ways:

```text
encrypted VM bytecode
    -> hides the real flag constraints
anti-debug state
    -> poisons the result if the environment looks wrong
```

The VM part is the real checker, but the anti-debug part is what makes the solve annoying. If I tried to reverse or test the checker while the poison was active, I could end up chasing fake failures.

Patching the conditional move at `0x401382` removes that extra sabotage and leaves the actual flag validation intact. Once the poisoned state is gone, the recovered input passes normally.

So the full chain is:

```text
inspect binary
    -> find encrypted VM checker
    -> notice anti-debug state feeds into final result
    -> patch cmove r15d, eax at offset 0x1382
    -> recover / test the VM constraints
    -> get Correct!
```

## Flag

```text
LYKNCTF{0UT_0F_C0NTR0L_VM2026}
```
