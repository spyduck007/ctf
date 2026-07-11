---
title: Miss My School
date: 2026-07-06
tags:
- osint
- LYKNCTF
---

- **Challenge:** Miss My School
- **Category:** OSINT
- **Flag:** `LYKNCTF{long_bien_elementary}`

---

## My initial read / first impressions

The challenge description says:

```text
Talking about home makes me remember my old elementary school.

Using either point B or point C from the previous challenge (miss my home) as the starting point, my elementary school is located within a 2 km radius of one of those two points.

I am 18 years old now, and I started first grade in 2013. Find the elementary school I used to attend.
```

So this was basically a follow-up OSINT challenge. The previous challenge gave possible home-area points, and now this one says the elementary school is within `2 km` of either point B or point C.

The attached image is clearly the front gate of a Vietnamese elementary school. The goal was not just to find any school nearby, but to identify the exact school from the visible details in the photo.

## Looking at the image

The first obvious clues were the banners:

```text
Ngày bầu cử đại biểu Quốc hội khóa XV
nhiệm kỳ 2021 - 2026

80 năm ngày thành lập Đội TNTP Hồ Chí Minh
15/5/1941 - 15/5/2021
```

These helped date the photo around 2021, but they did not identify the school directly. A lot of schools would have had the same political / anniversary banners.

The better clue was in the top right corner of the image. On the dark sign above the gate, there is a phone number:

```text
ĐT: (04) 38 750 348
```

That was the real lead. Instead of trying to manually compare every school courtyard within the radius, I searched the phone number.

## Searching the phone number

The old Hanoi area code was written as `(04)`, so the number can also appear in modern listings as:

```text
024 3875 0348
```

Useful searches were things like:

```text
"38 750 348" school Hanoi
"024 3875 0348" "tiểu học"
"(04) 38 750 348"
```

Those searches pointed to:

```text
Trường Tiểu học Long Biên
```

This also matched the image visually. The online listings / school pages show the same kind of entrance area, and the school name fits the Long Biên area from the previous challenge's points.

## Verifying the school name

The important thing here is that the flag asks for the English-style normalized school name:

```text
LYKNCTF{school_name_elementary}
```

The Vietnamese school name is:

```text
Trường Tiểu học Long Biên
```

Removing the generic `Trường Tiểu học` part and converting the actual school name gives:

```text
Long Biên -> long_bien
```

Then adding `_elementary` gives:

```text
long_bien_elementary
```

## Why this works

The 2 km radius clue narrows the map down, but the image itself gives the unique identifier. The banners are mostly noise because many schools had the same 2021 election / youth organization decorations.

The phone number is the clean pivot:

```text
(04) 38 750 348
    -> 024 3875 0348
    -> Trường Tiểu học Long Biên
    -> long_bien_elementary
```

So the solve is mostly about not overcomplicating the map search. Once I noticed the phone number, the school became unambiguous.

## Final flag

```text
LYKNCTF{long_bien_elementary}
```
