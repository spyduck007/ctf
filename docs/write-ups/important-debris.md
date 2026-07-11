---
title: IMPORTANT DEBRIS
date: 2026-07-06
tags:
- osint
- LYKNCTF
---

- **Challenge:** IMPORTANT DEBRIS
- **Category:** OSINT
- **Flag:** `LYKN{ITEM31_BAC27WPPS61_BMS4-20}`

---

## My initial read / first impressions

The challenge description says:

```text
Some MH370 records do not focus on the flight path, but on fragments recovered years later across the Indian Ocean region. One later debris report describes several pieces from Madagascar, and one item stands out because investigators could link a small marking to a Boeing cabin component.

Find that item and recover the item index, the full marker part number, and the Boeing material specification referenced in the report.
```

The important clues are:

```text
MH370
fragments recovered years later
Madagascar
small marking
Boeing cabin component
```

So this is not really about reconstructing the flight path. It is a document OSINT challenge. The goal is to find the right official MH370 debris report, then identify the item where investigators connected a marking on the debris to an actual Boeing part/material reference.

The flag format also tells us exactly what we need:

```text
LYKN{ITEM_MARKER_SPEC}
```

So I was looking for three values:

1. the item number/index
2. the full marker part number
3. the Boeing material specification

## Finding the correct report

Since the prompt specifically mentions Madagascar, I searched around for MH370 debris reports with that keyword.

Useful searches were things like:

```text
MH370 Madagascar debris report Boeing cabin component marking
MH370 Madagascar debris examination report VPPS61
MH370 debris report Madagascar Boeing material specification
```

This led to the official Malaysian Ministry of Transport MH370 debris examination report update.

The report has a section covering debris items recovered from Madagascar. That matched the prompt, so from there the solve was just searching inside the PDF for the marker / Boeing component language.

## Searching inside the report

Inside the PDF, the useful search terms were:

```text
Madagascar
marker
placard
BMS
cabin floor panel
VPPS61
```

The standout hit was an item with a visible marking that looked like:

```text
VPPS61
```

At first, this looks like it could be the full part number. But the report explains that this is only the visible/remaining part of the marker.

The actual full marker part number was:

```text
BAC27WPPS61
```

The report also explains why the visible marking looked slightly different. The missing/damaged part of the `W` made the marking look like `VPPS61`, but the Boeing marker format points to `BAC27WPPS61`.

## The important item

The item tied to this marker is:

```text
Item 31
```

The report connects the marker to a Boeing 777 cabin component, specifically a cabin floor panel marker/placard.

The Boeing material specification referenced with that marker is:

```text
BMS4-20
```

So the three pieces for the flag are:

```text
Item: ITEM31
Marker: BAC27WPPS61
Spec: BMS4-20
```

## Why this works

The tricky part of the challenge is that the obvious MH370 searches usually pull up flight path timelines, satellite analysis, and news articles. But the prompt is pointing away from that and toward recovered debris documentation.

Once I had the correct debris examination report, the solve became much simpler:

1. Find the MH370 debris report covering Madagascar items.
2. Search the report for Boeing-style markings/specs.
3. Notice the item where `VPPS61` is linked back to the full marker number.
4. Extract the item index, full marker part number, and Boeing material spec.

The reason `BAC27WPPS61` matters is that it is not just random text on the debris. It is a Boeing marker/placard part number associated with cabin floor panel material. The related Boeing material specification is `BMS4-20`, which is exactly the kind of value the flag format is asking for.

## Final flag

```text
LYKN{ITEM31_BAC27WPPS61_BMS4-20}
```