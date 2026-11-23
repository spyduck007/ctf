---
title: On the Rail Fence
date: 2026-11-20
tags:
- crypto
- WolvCTF-2026
---

- **Challenge:** On the Rail Fence
- **Category:** Crypto
- **Flag:** `wctf{the-victors}`

---

## My initial read / first impressions

The challenge asks for the name of a song and gives us this ciphertext:

```text
H!hcsiH!hnrheiatcaedaeatetvaateqiesliohnemntealtteitrvlataltteoq'igeosalHi!oihgnhlaesnbsHi!ohvcosainHi!ohcnurnhreHi!altMcia,hcaposfhWs!iovoaniocunrH!lMiterdtltirltlto'goaH!igthioet
```

The description also says to lowercase the song name, replace spaces with dashes, and submit it as `wolvctf{song}`.

The title basically gives away the cipher. A Rail Fence cipher writes the message in a zigzag across a few rows (rails), then reads each row straight across to make the ciphertext. We just need to figure out how many rails were used.

## Trying different rail counts

I tried decrypting it with a few different numbers of rails. With 2 rails, the text is still garbage. With 3, it immediately starts making sense:

```text
Hail!tothevictorsvaliantHail!totheconqu'ringheroesHail!Hail!toMichigantheleadersandbestHail!tothevictorsvaliantHail!totheconqu'ringheroesHail!Hail!toMichigan,thechampionsoftheWest!
```

There aren't any spaces in the decoded text because the original message was encrypted without them. But it's pretty easy to read once you know what you're looking at:

```text
Hail! to the victors valiant
Hail! to the conqu'ring heroes
Hail! Hail! to Michigan, the leaders and best
```

Those are the lyrics to *The Victors*, the University of Michigan fight song. That also fits the Michigan theme of the CTF.

## Solution script

I used this to try rail counts from 2 through 6. It works out which rail each character belongs to, splits the ciphertext into those rails, then follows the zigzag again to put the characters back in order.

```python
#!/usr/bin/env python3

ciphertext = (
    "H!hcsiH!hnrheiatcaedaeatetvaateqiesliohnemntealtteitrvlataltteoq'igeosal"
    "Hi!oihgnhlaesnbsHi!ohvcosainHi!ohcnurnhreHi!altMcia,hcaposfhWs!iovoaniocunr"
    "H!lMiterdtltirltlto'goaH!igthioet"
)


def decrypt(text, rails):
    path = []
    row = 0
    direction = 1

    for _ in text:
        path.append(row)
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction

    chunks = []
    offset = 0
    for rail in range(rails):
        count = path.count(rail)
        chunks.append(iter(text[offset:offset + count]))
        offset += count

    return "".join(next(chunks[rail]) for rail in path)


for rails in range(2, 7):
    print(f"{rails} rails: {decrypt(ciphertext, rails)}\n")
```

Run it with:

```bash
python3 solve.py
```

The 3-rail output is the one with the Michigan fight song lyrics.

## Formatting the flag

The song title is `The Victors`, so following the lowercase and dashes rule gives `the-victors`.

There was one annoying part: the prompt said to use `wolvctf{song}`, but `wolvctf{the-victors}` was rejected. The actual accepted prefix was `wctf`, so the correct submission was `wctf{the-victors}`.

## Final flag

```text
wctf{the-victors}
```
