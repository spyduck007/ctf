---
title: UNNAMED MERCHANT
date: 2026-07-06
tags:
- osint
- LYKNCTF
---

- **Challenge:** UNNAMED MERCHANT
- **Category:** OSINT
- **Flag:** `LYKN{HOEGH_ST_PETERSBURG_9420045_257366000_19_FILIPINO}`

---

## My initial read / first impressions

The challenge description says:

```text
AMSA's public MH370 timeline records that merchant ships responded to an Australian shipping broadcast during the first southern Indian Ocean search phase, but the timeline does not name every civilian surface asset.

Find the civilian vessel that was closest to the early southern Indian Ocean lead and find it IMO, MMSI number, number of crew and they nationality.
```

The important part here is that this is asking about the **early southern Indian Ocean search phase**, not the later underwater search or the later debris reports.

The flag format also tells us the exact pieces we need:

```text
LYKN{VESSEL_NAME_IMO_MMSI_NUMBER OF CREW_NATIONALITY}
```

So I was looking for five values:

1. vessel name
2. IMO number
3. MMSI number
4. number of crew
5. crew nationality

## Starting from AMSA

The prompt points directly to AMSA's public MH370 timeline, so I started there instead of just randomly searching ship names.

The timeline confirms that Australia was coordinating the southern Indian Ocean search and that merchant ships responded to an Australian shipping broadcast. The annoying part is that the timeline does not list every civilian ship by name, which is exactly what the challenge is hinting at.

So AMSA gave the right search phase and context, but not the full answer.

At this point the target became:

```text
the civilian / merchant vessel closest to the early southern Indian Ocean lead
```

## Finding the named ship

Useful searches were things like:

```text
MH370 merchant ship closest to search area
MH370 Australian shipping broadcast merchant ship
MH370 Hoegh St Petersburg search area
19 Filipinos Norwegian ship MH370
```

The useful articles pointed to a Norwegian merchant vessel named:

```text
Hoegh St. Petersburg
```

This matched the challenge really well because the articles describe it as the first / closest merchant ship sent toward the early southern Indian Ocean search area.

This also explains the wording of the challenge. AMSA's timeline mentions merchant ships responding, but the actual ship name has to be recovered from news / vessel reporting around that same search phase.

## Crew count and nationality

The crew detail was the part that could easily cause a wrong flag.

One source trail gives a crew count of `20`, but the source that matched the final checker says there were:

```text
19 Filipinos
```

So for the flag, the crew fields are:

```text
Crew count: 19
Nationality: FILIPINO
```

The nationality is singular in the flag even though the source wording says Filipinos.

## Vessel identifiers

After getting the vessel name, the rest was normal vessel lookup.

Searching the vessel name led to the ship tracking / vessel database entry for **Hoegh St. Petersburg**, which gave:

```text
IMO: 9420045
MMSI: 257366000
```

The vessel name has a period in normal writing:

```text
Hoegh St. Petersburg
```

But the flag format wants uppercase words separated by underscores, so it becomes:

```text
HOEGH_ST_PETERSBURG
```

## Putting the flag together

The final parts are:

```text
Vessel: HOEGH_ST_PETERSBURG
IMO: 9420045
MMSI: 257366000
Crew: 19
Nationality: FILIPINO
```

So the final flag is:

```text
LYKN{HOEGH_ST_PETERSBURG_9420045_257366000_19_FILIPINO}
```

## Why this works

The main trick is that the official AMSA page is only the starting point. It tells us the correct moment in the MH370 timeline and confirms that merchant ships responded, but it does not directly name the vessel we need.

From there, the solve is basically an OSINT pivot:

1. Use AMSA to identify the early southern Indian Ocean search phase.
2. Search around that phase plus merchant ship / closest ship wording.
3. Find the named civilian vessel, **Hoegh St. Petersburg**.
4. Look up the vessel's IMO and MMSI.
5. Use the article/source trail with the correct crew count: `19` Filipino crew.

The formatting trap is also very real here. `Hoegh St. Petersburg` needs to become `HOEGH_ST_PETERSBURG`, and the accepted crew count is `19`, not `20`.

## Final flag

```text
LYKN{HOEGH_ST_PETERSBURG_9420045_257366000_19_FILIPINO}
```
