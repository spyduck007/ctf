---
title: waypoint
date: 2026-06-28
tags:
- misc
- MntcrlCTF-2026
---

* **Challenge:** Waypoint
* **Category:** Misc
* **Flag:** `mntcrl{n3v3r_tru5t_4_p1l0t}`

---

## My initial read / first impressions

We are given the challenge description:

```text
A pilot says he just did "some tests" on the university campus.

The flight logs tell a different story.

Recover the message he was trying to send.

Flag format: mntcrl{...}
```

So this already sounds like some kind of GPS / geolocation challenge.

The provided file was a zip containing a bunch of DJI flight record CSVs:

```text
DJIFlightRecord_2024-06-12_10-39-07_FRF68D9D9B034131.csv
DJIFlightRecord_2024-06-12_10-42-25_FR1E399698E3B36A.csv
DJIFlightRecord_2024-06-12_10-54-21_FRE8D449F7285887.csv
...
```

There were 51 CSV files total, and each one looked like a normal drone log.

The columns were:

```text
flightTime[ms], utcTime, latitude, longitude, height[m], speed[m/s], pitch[deg], roll[deg], yaw[deg], batteryLevel[%], flightMode
```

The important columns are obviously:

```text
latitude
longitude
```

## The obvious idea

Since the prompt says the pilot was doing "some tests", but the logs tell a different story, the first thought is that the flight path itself is the message.

Each CSV contains a sequence of GPS points. If we plot longitude on the x-axis and latitude on the y-axis, we should be able to see the shape of the drone path.

So the plan was:

1. Unzip all the CSV files.
2. Read every latitude / longitude point.
3. Plot all points in chronological file order.
4. Look at the image and see if it spells anything.

This is one of those challenges where the data itself is not really hidden. The trick is just realizing that the coordinates are the drawing.

## Looking at the logs

A random row looked like this:

```text
0,2024-06-12 10:39:07.000,41.1082952,16.8809869,29.97,2.73,2.94,-0.88,0.00,92,GPS_MODE
```

So the drone is around:

```text
41.108..., 16.880...
```

The exact location does not really matter for the solve, but it confirms these are real GPS-style coordinates.

The important part is that every file is basically a small stroke of the final drawing. If you plot one file at a time, it looks like just random short paths. But plotting everything together makes the message show up.

## Plotting the flight path

I used Python with `matplotlib` to draw all the paths.

The only slightly important detail is that longitude should be the x-axis and latitude should be the y-axis. If you swap them, the image is rotated / weird and harder to read.

Here is the solve script I used:

```python
import csv
import glob
import os

import matplotlib.pyplot as plt


files = sorted(glob.glob("*.csv"))

plt.figure(figsize=(16, 8))

for path in files:
    xs = []
    ys = []

    with open(path, newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            lat = row.get("latitude")
            lon = row.get("longitude")

            if not lat or not lon:
                continue

            lat = float(lat)
            lon = float(lon)

            if lat == 0 or lon == 0:
                continue

            xs.append(lon)
            ys.append(lat)

    if xs and ys:
        plt.plot(xs, ys, linewidth=2)

plt.axis("equal")
plt.gca().invert_xaxis()
plt.tight_layout()
plt.savefig("waypoint.png", dpi=300)
plt.show()
```

Running it inside the unzipped folder:

```bash
python solve.py
```

This creates:

```text
waypoint.png
```

And the plotted flight paths clearly spell out the message.

## Reading the message

The output image had the flag written across the campus using the drone paths.

The message was:

```text
n3v3r tru5t 4 p1l0t
```

So wrapping it in the required flag format gives:

```text
mntcrl{n3v3r_tru5t_4_p1l0t}
```

## Why this works

Each flight log is just a series of GPS coordinates sampled over time.

The pilot was not just flying random tests. He was flying paths shaped like letters. The challenge gives a bunch of separate logs instead of one clean image, so the data looks boring until you plot everything together.

The key idea is:

```text
longitude = x
latitude = y
```

Once the points are plotted in the right coordinate space, the flight path becomes text.

## Final solve script

Here is the final cleaned-up script:

```python
import csv
import glob

import matplotlib.pyplot as plt


def read_points(path):
    xs = []
    ys = []

    with open(path, newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            try:
                lat = float(row["latitude"])
                lon = float(row["longitude"])
            except:
                continue

            if lat == 0 or lon == 0:
                continue

            xs.append(lon)
            ys.append(lat)

    return xs, ys


def main():
    files = sorted(glob.glob("*.csv"))

    plt.figure(figsize=(16, 8))

    for path in files:
        xs, ys = read_points(path)

        if xs:
            plt.plot(xs, ys, linewidth=2)

    plt.axis("equal")
    plt.gca().invert_xaxis()
    plt.tight_layout()
    plt.savefig("waypoint.png", dpi=300)

    print("saved plot to waypoint.png")
    print("flag: mntcrl{n3v3r_tru5t_4_p1l0t}")


if __name__ == "__main__":
    main()
```

Running it:

```bash
python solve.py
```

Output:

```text
saved plot to waypoint.png
flag: mntcrl{n3v3r_tru5t_4_p1l0t}
```

And that gives the flag:

```text
mntcrl{n3v3r_tru5t_4_p1l0t}
```
