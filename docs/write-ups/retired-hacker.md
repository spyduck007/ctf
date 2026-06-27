---
title: Retired Hacker
date: 2026-06-26
tags:
- osint
- TraceBash-CTF-2026
---

- **Challenge:** Retired Hacker
- **Category:** OSINT
- **Flag:** `TBCTF{Piața_Gheorghe_Domășneanu}`

---

## My initial read / first impressions

We are given a leaked chat screenshot between two people. One of them is asking if the other person is still alive because they have not heard from them since some forum got taken down. The other person, `JJ ^_^`, says they are still around, but they have been laying low and are basically done with the hacking scene.

The important part of the conversation is this message:

`i use komoot, it's sick for logging routes and plannew new ones. here's my profile if you wanna see my trails or follow me`

Then they drop this profile link:

`https://www.komoot.com/user/5667624959835`

## Following the Komoot profile

The first thing I did was open the Komoot link from the screenshot.

The profile belonged to **Jim Lee**, and the bio matched the challenge perfectly because it talked about him being an ex-hacker trying to turn his life around and spend more time outdoors.

The Komoot profile also had another very useful clue: a linked GitHub account.

The GitHub username was:

`jiml33t`

At this point, we had the person's name and a username to pivot from.

## Checking GitHub

The GitHub account did not look super interesting at first. There was only one profile-style repo, so I checked the repository and its commit history.

This is a classic OSINT thing with GitHub. Even if the profile page does not show an email, old commits can still expose the email that was configured locally in Git.

One easy way to check this is to open the commit as a patch file:

```text
https://github.com/jiml33t/jiml33t/commit/<commit_hash>.patch
```

The patch showed the author metadata and exposed the email:

```text
jimleepro1@gmail.com
```

That confirmed another identity link. The username `jimleepro1` also gave another name pattern to keep in mind, but the main reusable handle was still `jiml33t`.

## Pivoting from the username

The next move was to search for the reused username:

```text
jiml33t
```

This led to a Threads account using the same handle. That was the account that had the actual location clue.

On Threads, there was a post dated **05/07/26**, which matched the challenge date, May 7, 2026.

The post said something along the lines of him finishing his last run before the big day and hopping on the tram for coffee at his favourite French supermarket.

This gave two important clues:

- He was using a tram.
- He was going to a French supermarket.

The French supermarket clue matters because **Auchan** is a French supermarket chain.

## Geolocating the image

The Threads post also had an attached image. The image had a visible sign/building text:

```text
IRIGATII.RO
```

Searching that led to a location in **Timișoara, Romania**. This also matched the Romanian phone/country-code trail from the email side of the challenge, so the location was not random.

The image location placed us around the Calea Buziașului / Calea Stan Vidrighin area in Timișoara. There was also an Auchan nearby, which lined up perfectly with the "favourite French supermarket" hint from the post.

So now the logic was:

1. The Threads post is from May 7, 2026.
2. The post mentions taking the tram.
3. The post mentions a French supermarket.
4. The image geolocates to Timișoara.
5. The nearby French supermarket is Auchan.
6. We need the tram station where he got off.

## Finding the tram station

Once I had the location, I checked the nearby tram stops around the Auchan / geolocated area.

The relevant station name was:

```text
Piața Gheorghe Domășneanu
```

This was the part that was slightly annoying because some maps/listings show extra text like route labels or nearby terminus information, but the flag wanted the actual base station name.

Also, the flag checker wanted the Romanian diacritics exactly. The ASCII-normalized version did not work.

So the final station name had to be:

```text
Piața Gheorghe Domășneanu
```

## Final Flag

The challenge format wanted underscores between words:

```text
TBCTF{Piața_Gheorghe_Domășneanu}
```

## Takeaways

This was a pretty straightforward but clean OSINT chain. The first clue was sitting directly in the screenshot, but the actual solve required a few pivots:

- Komoot gave the real name and GitHub profile.
- GitHub commit metadata leaked the email.
- Username reuse led to Threads.
- The Threads post gave the exact date and tram clue.
- The image gave the geolocation through `IRIGATII.RO`.
- The "French supermarket" hint pointed toward Auchan.
- The final answer was the nearby tram station, with exact Romanian diacritics.

The main trap was the flag formatting. Usually I would try to normalize the station name to ASCII for a CTF flag, but here the correct flag kept the diacritics:

```text
TBCTF{Piața_Gheorghe_Domășneanu}
```
