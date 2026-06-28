---
title: Capa Spotted
date: 2026-06-28
tags:
- osint
- MntcrlCTF-2026
---

- **Challenge:** Capa Spotted
- **Category:** OSINT
- **Flag:** `mntcrl{7, Via Bettino Ricasoli, Molfetta}`

---

## My initial read / first impressions

We are only given a YouTube link:

```text
https://www.youtube.com/watch?v=GaXuMC_GHEE
```

And the flag format is:

```text
mntcrl{Number, Address, City}
```

So this is clearly not a normal “watch the video and find hidden text” type challenge. The format is asking for a physical location, specifically a house/building number, street address, and city.

The example also uses an Italian address:

```text
mntcrl{10, Via Giuseppe Verdi, Monza}
```

So from the start I assumed this was probably a geolocation challenge based around the music video, artist, filming location, or some specific place connected to the video.

Opening the link shows the video is:

```text
Caparezza - Jodellavitanonhocapitouncazzo
```

Caparezza is Italian, so the Italian address format immediately makes sense.

## Looking at the video

The first thing I checked was whether the video itself had an obvious location. Sometimes these challenges hide the answer in:

- the video description
- pinned comments
- visible storefronts/signs
- license plates
- street signs
- filming locations
- artist hometown connections

But here the title and artist ended up being more important than frame-by-frame video analysis.

The key clue is that the challenge gives only the YouTube link, not a screenshot or timestamp. That usually means the answer is connected to public information about the video or artist, rather than one tiny visual detail hidden somewhere.

So I started searching around the exact video/title and Caparezza.

## The OSINT trail

Searching for Caparezza and the video led to an odd but very useful fact: Caparezza had apparently been spotted on Google Street View.

This stood out because the challenge is asking for an address, and Street View is exactly the kind of thing that would give a precise number/street/city.

The important search terms were basically:

```text
Caparezza Jodellavitanonhocapitouncazzo location
```

and then:

```text
Caparezza Google Street View address
```

This led to articles about Caparezza being visible on Google Street View in Molfetta.

One article specifically mentions:

```text
Via Bettino Ricasoli 7
```

Another source also points to the same street in Molfetta, near a music school / studio area.

So now the answer was almost solved:

* Number: `7`
* Address: `Via Bettino Ricasoli`
* City: `Molfetta`

## Verifying the address

Since the flag format is very strict, I wanted to make sure I did not mess up the order or formatting.

The challenge wants:

```text
mntcrl{Number, Address, City}
```

So not:

```text
mntcrl{Via Bettino Ricasoli 7, Molfetta}
```

and not:

```text
mntcrl{7 Via Bettino Ricasoli, Molfetta}
```

It has to be split like the example:

```text
mntcrl{10, Via Giuseppe Verdi, Monza}
```

Following that exact format gives:

```text
mntcrl{7, Via Bettino Ricasoli, Molfetta}
```

## Final flag

```text
mntcrl{7, Via Bettino Ricasoli, Molfetta}
```
