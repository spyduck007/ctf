---
title: The Mission Begins
date: 2025-12-01
tags:
  - crypto
  - Advent-of-CTF-2025
---

**Challenge:** The Mission Begins  
**Category:** Crypto  
**Flag:** `csd{W3lc0m3_8aCK_70_adv3N7_2025}`

---

## My initial read / first impressions

We’re given a single file, `start.txt`, which contains what looks like space-separated binary:  
```
00110101 00111001 00110011 00110011 00110100 01100101 00110110 01100010 00110110 00110101 00110011 00110001 00110110 00110011 00110111 01100001 00110110 00110010 00110100 00110111 00110100 01100100 00110111 00110111 00110110 00110010 00110101 00110100 00110100 01100101 00110110 00110110 00110100 01100110 00110100 00110111 00110100 00110110 00110100 00110100 00110101 00110011 00110011 00110001 00110011 00111000 00110011 00110011 00110100 01100100 00110100 00110110 00110011 00111001 00110110 00111000 00110101 01100001 00110100 00111000 00110101 00111001 00110111 01100001 00110101 00110100 00110110 01100001 00110110 00110100 00110110 00110110 00110100 01100100 00110110 01100001 00110100 00110001 00110111 00111001 00110100 01100101 00110101 00111000 00110011 00110000 00110011 01100100
```
Given the format (8-bit chunks separated by spaces), the obvious first step is to interpret each chunk as a byte.  

## Step 1 – Binary → text

Each 8-bit value can be interpreted as an ASCII character. Doing that yields:  
```
59334e6b6531637a62474d7762544e664f474644533138334d4639685a48597a546a64664d6a41794e58303d
```
This is clearly hexadecimal (only `0–9` and `a–f` characters, typical length).  

So the first layer is:  
- __From Binary (space-separated bytes)__ → ASCII string that looks like hex.  

## Step 2 – Hex → bytes

Next, we treat that string as hex and decode it to raw bytes. In text form, that gives us:  
```
Y3Nke1czbGMwbTNfOGFDS183MF9hZHYzTjdfMjAyNX0=
```

This very much looks like Base64:  
- Ends with `=`  
- Only `A–Z`, `a–z`, `0–9`, `+`, `/`, `=`  

So the second layer is:  
- __From Hex__ → Base64 string.  

## Step 3 – Base64 → flag

Finally, we decode the Base64 string:  
```
csd{W3lc0m3_8aCK_70_adv3N7_2025}
```
That’s a properly formatted flag, so we’re done.

## CyberChef recipe

This chain of encodings is exactly what CyberChef solves nicely. The working recipe is:  
1. `From_Binary('Space')`  
2. `From_Hex('None')`  
3. `From_Base64('A-Za-z0-9+/=',true,false)`

Feeding the original `start.txt` contents through that recipe produces:
```
csd{W3lc0m3_8aCK_70_adv3N7_2025}
```