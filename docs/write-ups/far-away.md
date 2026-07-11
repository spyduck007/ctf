---
title: Far Away
date: 2026-07-06
tags:
- osint
- LYKNCTF
---

- **Challenge:** Far Away
- **Category:** OSINT
- **Flag:** `LYKNCTF{ba_vi_1296m}`

---

## My initial read / first impressions

The challenge description says:

```text
I love looking out of the window whenever I’m stuck at my university. Nature is so beautiful. It makes me wonder: when was the last time I actually touched grass? Far away, there is a mountain — a really big mountain. I’m curious about the name of that mountain, and how high it is.
```

We are also given two images:

1. a photo taken out of a university window with a mountain in the distance
2. a campus map of **FPT University Hanoi**, with a parking lot circled

The flag format asks for:

```text
LYKNCTF{mountain_name_heightm}
```

So the goal is not to identify the exact building or room. The goal is to figure out what mountain is visible from the university, then get the height of the highest peak of that mountain.

## Locating the university

The second image basically gives away the starting location. It is a map titled:

```text
Bản đồ Trường Đại học FPT cơ sở Hà Nội
```

The address on the image is:

```text
Khu Giáo dục và Đào Tạo - Khu Công nghệ cao Hòa Lạc - Km29 Đại lộ Thăng Long, Thạch Thất, Tp Hà Nội
```

So the university is **FPT University Hanoi** in the Hoa Lac area.

The hint says to use the circled point as the university parking lot and then project the view toward the mountain. That means the map image is not just decoration. It tells us where to stand / orient the view from.

## Matching the photo direction

In the window photo, the mountain is far away and slightly hazy, but the shape is pretty distinctive. It is a wide mountain mass with several bumps/peaks instead of one sharp isolated cone.

Using Google Maps / Google Earth around the FPT University Hanoi campus, I started from the parking lot area shown in the campus map and looked outward in the same general direction as the window photo.

Looking west / northwest from the Hoa Lac campus points toward a large mountain range outside Hanoi. In Google Earth 3D, the skyline in that direction lines up with the mountain visible in the photo.

That mountain range is:

```text
Ba Vì
```

This also makes geographic sense. FPT University Hanoi is in Hoa Lac / Thach That, and Ba Vì is the major mountain range visible in the distance from that side of Hanoi.

## Getting the height

The challenge asks for the height of the **highest peak of that mountain**, not just a random point on the range.

For Ba Vì, the highest peak is usually listed as **Đỉnh Vua** / **Vua Peak**, with a height of:

```text
1296 m
```

So the pieces for the flag are:

```text
Mountain: ba_vi
Height: 1296m
```

## Why this works

The important part is using the campus map to avoid guessing from the photo alone. A mountain skyline by itself is pretty vague, especially with haze and a cropped window view.

The solve path is:

```text
campus map
    -> FPT University Hanoi, Hoa Lac
    -> circled parking lot as the starting point
    -> project the window/photo direction in Google Earth 3D
    -> visible mountain range is Ba Vì
    -> highest peak is 1296 m
```

The formatting is also worth watching. The flag wants lowercase and underscores, so `Ba Vì` becomes `ba_vi`, and the height keeps the `m` unit attached.

## Final flag

```text
LYKNCTF{ba_vi_1296m}
```
