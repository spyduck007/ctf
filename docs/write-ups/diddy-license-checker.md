---
title: Diddy License Checker
date: 2026-06-26
tags:
- misc
- V1T-CTF-2026
---

- **Challenge:** Diddy License Checker
- **Category:** Misc
- **Flag:** `v1t{435_f1b0_w3bs1t3}`

---

## My initial read / first impressions

We are given a binary called `diddy`. Running it gives a goofy little license checker that asks three questions:

1. What type of animal was your first pet?
2. What is your lucky number?
3. What is your license name?

The website also shows a few hints like `295`, `giggle`, and the whole "Diddy License Checker" theme.

At first, I assumed this was just going to be a basic reversing challenge where the binary checks a few hardcoded strings. That was kind of true, but not fully. The first two checks are pretty simple, but the third part involves a license URL, some XOR, and AES-CBC decryption.

So the challenge is basically a mix of reversing, web, and crypto.

## Reversing the first input

I started with the simplest thing: checking strings and the main function.

The first check is very direct. The binary asks:

```text
1. What type of animal was your first pet?
```

and then compares the input to:

```text
duck
```

So the first input is:

```text
duck
```

Nothing too crazy yet.

## Reversing the lucky number

The second prompt is:

```text
2. What your lucky number ?
```

The binary checks that the lucky number starts with `0`, and then it checks each following digit against a Fibonacci-style sequence modulo 9.

The value is basically:

```text
0 + F1..F31 mod 9
```

That produces:

```text
01123584371808876415628101123584
```

So the second input is:

```text
01123584371808876415628101123584
```

This also explains why the number looks random at first but has the classic `0112358` Fibonacci start.

## Reversing the license part

The third prompt is:

```text
3. Enter your license name:
```

This is where the challenge gets more interesting.

In the binary, there is a base64 string:

```text
aHR0cDovL3YxdC5zaXRlLw==
```

Decoding it gives:

```text
http://v1t.site/
```

Then the binary appends the license name to that base URL and makes a request to it.

The correct license name is:

```text
license-for-user-deadbeef-diddy
```

So the URL becomes:

```text
http://v1t.site/license-for-user-deadbeef-diddy
```

That page gives this hex string:

```text
7631745f3433355f6b33795f66726672
```

Decoding that hex gives:

```text
v1t_435_k3y_frfr
```

So this is the AES key.

## The actual decryption

The binary has an embedded array called `arr`. This array is not the ciphertext directly.

Instead, the binary XORs the array with the license name:

```text
license-for-user-deadbeef-diddy
```

That gives a hex string:

```text
9fad7f446b751ae0f12d06736710eb70110cd73f69976c5bfed1c5dc6432b8823d1378094fa60d347d9b4da3399db570
```

This hex string is the AES ciphertext.

Now we have all the AES-CBC pieces:

* **Key:** from the website
* **IV:** the lucky number
* **Ciphertext:** the XOR result from the binary

The IV is:

```text
01123584371808876415628101123584
```

The key is:

```text
7631745f3433355f6b33795f66726672
```

The decrypted plaintext is still not directly the flag. It decrypts to another hex string:

```text
7631747b3433355f663162305f773362733174337d
```

Decoding that final hex gives the real flag:

```text
v1t{435_f1b0_w3bs1t3}
```

## Solution Script

Here is the final solve script.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

arr = [
    85, 15, 2, 1, 89, 21, 81, 25, 80, 13, 69, 24,
    68, 18, 0, 66, 75, 85, 87, 5, 84, 84, 82, 86,
    80, 26, 85, 89, 1, 6, 78, 92, 88, 82, 85, 13,
    23, 82, 30, 0, 89, 75, 20, 66, 69, 6, 71, 79,
    2, 0, 5, 85, 1, 80, 1, 5, 27, 80, 90, 86,
    6, 65, 84, 91, 80, 1, 95, 64, 82, 21, 86, 86,
    70, 75, 20, 69, 85, 22, 30, 80, 82, 5, 93, 0,
    81, 1, 7, 30, 87, 80, 93, 0, 27, 89, 94, 83
]

license_name = b"license-for-user-deadbeef-diddy"
iv = bytes.fromhex("01123584371808876415628101123584")
key = bytes.fromhex("7631745f3433355f6b33795f66726672")

ct_hex = bytes(x ^ license_name[i % len(license_name)] for i, x in enumerate(arr))
ct = bytes.fromhex(ct_hex.decode())

cipher = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(ct), 16)

flag = bytes.fromhex(pt.decode()).decode()
print(flag)
```

Running it prints:

```text
v1t{435_f1b0_w3bs1t3}
```

## Flag

```text
v1t{435_f1b0_w3bs1t3}
```