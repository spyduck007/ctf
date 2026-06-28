---
title: nfz
date: 2026-06-28
tags:
- forensics
- MntcrlCTF-2026
---

- **Challenge:** nfz
- **Category:** Forensics
- **Flag:** `mntcrl{un4uth0r1z3d_fl1gh7}`

---

## My initial read / first impressions

We are given a compressed SD card image from a DJI Mavic 3.

The description says:

```text
A drone operator was caught flying near a restricted airspace perimeter. The microSD card from his DJI Mavic 3 was seized.

He claims he was just taking landscape photos, but the analyst noticed the storage media has more to say than what's on the surface.
```

So this immediately sounds like a disk forensics challenge.

The important wording is:

```text
more to say than what's on the surface
```

That usually means we should not just look at the visible files. We probably need to check deleted files, filesystem slack, metadata, thumbnails, or something embedded inside the media.

The file we get is:

```text
sdcard.img.gz
```

So first I decompressed it and checked what kind of image it was.

```bash
gunzip -k sdcard.img.gz
file sdcard.img
```

The image was an SD card filesystem, and it was using exFAT, which makes sense for a camera/drone SD card.

## Looking at the filesystem

Since this is a raw disk image, the first thing I wanted to do was inspect the filesystem normally before doing any carving.

```bash
mkdir extracted
mmls sdcard.img
```

Then I listed the files with SleuthKit:

```bash
fls -r sdcard.img
```

The visible structure looked like a normal DJI SD card:

```text
/DCIM/100MEDIA/
```

Inside that folder there were a bunch of DJI photos like:

```text
DJI_0018.JPG
DJI_0024.JPG
DJI_0030.JPG
```

At first glance, this matched the operator's story. It looked like landscape photos from a drone.

But because the prompt specifically said there was more than what was on the surface, I checked for deleted entries too.

```bash
fls -rd sdcard.img
```

That showed deleted DJI image entries, including:

```text
DJI_0017.JPG
```

That was already suspicious because normal visible photos were just landscape stuff, but the deleted files were probably where the actual evidence was hidden.

## Recovering deleted files

I recovered the deleted JPGs using `icat`.

```bash
icat sdcard.img <inode> > DJI_0017.JPG
```

I repeated that for the deleted DJI files that looked relevant.

Some of the recovered images were damaged or only partially recoverable, which is pretty normal in filesystem forensics. A deleted file entry can still exist even if the actual file data is partially overwritten.

So opening the recovered main image did not immediately give the flag.

At this point, the obvious next step was metadata.

## Checking EXIF data

Since these are DJI photos, EXIF metadata is extra important. Drone images often store GPS coordinates, timestamps, camera model data, and sometimes thumbnails.

I checked the recovered deleted image with `exiftool`.

```bash
exiftool DJI_0017.JPG
```

There was an embedded thumbnail inside the EXIF data.

That was the key.

The main recovered image was not very useful, but the embedded EXIF thumbnail was still intact. So I extracted it:

```bash
exiftool -b -ThumbnailImage DJI_0017.JPG > thumb.jpg
```

Then I opened `thumb.jpg`.

And that was it. The thumbnail showed the hidden message / flag.

## Why this worked

The trick was that the analyst should not trust only the allocated files.

The visible photos were boring landscape pictures, but the SD card still had deleted file records. One of those deleted images, `DJI_0017.JPG`, still contained an embedded EXIF thumbnail.

Even though the actual deleted photo was damaged, the thumbnail inside the metadata survived.

So the solve path was basically:

1. Decompress the SD card image.
2. Identify the filesystem.
3. List visible DJI media.
4. Check deleted filesystem entries.
5. Recover deleted `DJI_0017.JPG`.
6. Inspect EXIF metadata.
7. Extract the embedded thumbnail.
8. Read the flag from the thumbnail.

This is a really classic forensics idea: the interesting data is not always in the file content itself. Sometimes the leftover metadata is enough.

## Final commands

These are the commands that mattered:

```bash
gunzip -k sdcard.img.gz
file sdcard.img
mmls sdcard.img
fls -r sdcard.img
fls -rd sdcard.img
icat sdcard.img <inode> > DJI_0017.JPG
exiftool DJI_0017.JPG
exiftool -b -ThumbnailImage DJI_0017.JPG > thumb.jpg
```

Opening the extracted thumbnail showed the flag:

```text
mntcrl{un4uth0r1z3d_fl1gh7}
```

And that solves the challenge.
