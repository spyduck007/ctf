---
title: I HATE THIS APP
date: 2026-07-06
tags:
- rev
- LYKNCTF
---

- **Challenge:** I HATE THIS APP
- **Category:** Rev
- **Flag:** `LYKNCTF{setwindowdisplayaffinity}`

---

## My initial read / first impressions

The challenge description says:

```text
Aughhh, how the hell can I not take a screenshot of this freaking app? I... I mean... It feels like the app is transparent to my screen. I can see it, but I can’t capture it. Why? Am I living in a simulation or something?

Your mission is to find the function that prevents me from taking screenshots.
```

So the goal was not to recover some hidden text from the UI or bypass the app visually. The challenge was asking for the exact function responsible for making the app disappear from screenshots.

The important clue is this part:

```text
I can see it, but I can’t capture it
```

That sounds like a Windows screen-capture protection API. Some apps can mark their window so that normal screenshot / recording tools either show a black box or do not capture the window at all.

## Extracting the app

The provided file was:

```text
fuoverflow_learning.rar
```

After extracting it, I started treating it like a normal reversing challenge and looked for anything related to screenshots, capture protection, or Windows UI APIs.

A quick strings/imports check was enough to find the important lead:

```text
user32.dll
SetWindowDisplayAffinity
```

That immediately stood out because `user32.dll` is where a lot of Windows GUI/window-management APIs live, and `SetWindowDisplayAffinity` is specifically related to controlling where a window's contents are allowed to be displayed.

## Finding the screenshot-blocking call

In the disassembly/decompiler, the interesting call was basically:

```c
SetWindowDisplayAffinity(hwnd, 0x11);
```

The first argument is the window handle, and the second argument is the display affinity value.

The value `0x11` is the important part. That corresponds to:

```text
WDA_EXCLUDEFROMCAPTURE
```

That mode tells Windows to exclude the window from screen capture. So the window can still be visible normally on the user's monitor, but when a screenshot or recording tries to capture the screen, the protected window does not show up properly.

That matches the challenge description perfectly. The app feels "transparent" to screenshots because Windows is intentionally excluding that window from capture.

## Why this works

This was less about breaking encryption or patching the binary and more about recognizing the Windows API being used.

The full logic is:

```text
app creates/shows a window
    -> gets the window handle
    -> calls SetWindowDisplayAffinity
    -> passes 0x11 / WDA_EXCLUDEFROMCAPTURE
    -> Windows hides the window from screenshots
```

So the function preventing screenshots is:

```text
SetWindowDisplayAffinity
```

The challenge asks for all lowercase with no spaces, so the function name becomes:

```text
setwindowdisplayaffinity
```

## Flag

```text
LYKNCTF{setwindowdisplayaffinity}
```
