---
title: Control Freak 2
date: 2026-07-06
tags:
- rev
- LYKNCTF
---

- **Challenge:** Control Freak 2
- **Category:** Rev
- **Flag:** `LYKNCTF{1S_1T_H4RD_T0_C0NTR0L}`

---

## My initial read / first impressions

The challenge description says:

```text
The checker looks simple: give it a flag, get Correct or Nope. But the control flow does not like being watched, and every wrong move quietly changes the truth. Can you take back control?
```

We are given two binaries:

```text
chall-3
chall-3.exe
```

Since there was both a Linux and Windows build, I focused on the Linux one first. Running it normally is very simple:

```text
flag:
```

A wrong flag prints `Nope`, and a right flag should print `Correct!`. So from the outside it looks like a normal flag checker.

Obviously, it was not that friendly.

The description was already hinting at the real gimmick: the program does not like being watched, and wrong moves change the truth. That made me avoid relying too much on debugging at first, because anti-debug checks in rev challenges usually do not just crash the program. A lot of the time they quietly poison some state and make the real check lie to you.

## Finding the checker

The control flow is flattened pretty heavily. Instead of a clean sequence of checks, the binary bounces around a state machine that decides what block to run next.

The overall shape is:

```text
read input
    -> run anti-debug / environment checks
    -> build a seed/state value
    -> generate a shuffled lookup table
    -> transform the input bytes
    -> compare against an embedded target
    -> print Correct or Nope
```

The important part is that the anti-debug checks are mixed into the same state that the real flag checker uses. So the anti-debug logic is not just there as a side quest. If it fires, the expected values change and the correct flag will not look correct anymore.

That is what the description means by every wrong move quietly changing the truth.

## The anti-debug state

The binary checks for a few normal debugging / instrumentation signs, including:

```text
/proc/self/status / TracerPid
ptrace(PTRACE_TRACEME)
LD_PRELOAD
LD_AUDIT
```

These checks feed into a seed value. For the real success path, that seed needs to stay clean. If I tried to trace the binary normally, the checker would not simply say "debugger detected." It would keep going, but with poisoned state.

That is much more annoying because it makes testing misleading. You can recover something that looks close to the real logic, run it under the wrong conditions, and still only get `Nope`.

So I treated the binary as something to solve mostly statically. The goal was to recover the transformation and expected bytes without letting the anti-debug logic affect the answer.

## Recovering the transformation

Once I got past the flattened control flow, the real check was basically:

```text
input byte
    -> lookup through generated table
    -> compare transformed byte against target byte
```

The table is a 256-byte permutation generated using SplitMix64-looking constants. Since it is a permutation, it can be inverted. That means instead of brute-forcing the flag, I could generate the same table, invert it, and map each target byte back to the original input byte.

There was one annoying detail: the target buffer is not just a clean string sitting in `.rodata`.

The program writes the target with overlapping vector/SIMD stores, so if I just copied the visible bytes from the binary in order, I got the wrong target. The later overlapping write replaces part of the earlier data.

So the correct process was:

```text
reconstruct the generated table
    -> reconstruct the final target buffer after overlapping writes
    -> invert the table
    -> apply inverse[target[i]] for each byte
    -> recover the flag
```

After doing that, the recovered input was:

```text
LYKNCTF{1S_1T_H4RD_T0_C0NTR0L}
```

## Verifying it

Then I tested the recovered flag normally, without debugging/instrumentation getting in the way:

```bash
printf 'LYKNCTF{1S_1T_H4RD_T0_C0NTR0L}\n' | ./chall-3
```

The output was:

```text
flag: Correct!
```

So the recovered bytes were right.

## Why this works

The challenge has two layers:

```text
control-flow flattening
    -> makes the checker annoying to follow
anti-debug state mixed into validation
    -> makes dynamic analysis lie if the program notices it
```

The actual flag check is not impossible once separated from the noise. It is just a byte transformation through a generated permutation and a target compare.

The trick is not trusting the runtime result while the anti-debug paths are active. If the state gets poisoned, the binary is still running the checker, but it is no longer checking against the same truth.

So the solve was basically:

```text
inspect the flattened checker
    -> identify anti-debug/environment seed
    -> avoid letting that seed poison the solve
    -> rebuild the 256-byte permutation
    -> account for the overlapping target writes
    -> invert the transform
    -> get Correct!
```

## Flag

```text
LYKNCTF{1S_1T_H4RD_T0_C0NTR0L}
```
