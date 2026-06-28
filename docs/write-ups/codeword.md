---
title: Codeword
date: 2026-06-28
tags:
- crypto
- MntcrlCTF-2026
---

- **Challenge:** Codeword
- **Category:** Crypto
- **Flag:** `mntcrl{w3_h4v3_g4mbl1ng_1ssu3s_e7a0892f28e446c4}`

---

## My initial read / first impressions

We are given a remote service:

```bash
ncat --ssl codeword-9dbe0c03a320.c.mntcrl.it 443
```

The description says:

```text
You reached the MntCasino, an exclusive place only accessible to designated people.
To confirm you are entitled to get in, you must solve a word game!
```

Connecting to it gives this:

```text
You reached the MntCasino.
This exclusive place is only accessible to designated people.

To confirm you are entitled to get in, you must solve the codeword game!
------------------------------------------------------------------------------------------
Say 5 words, and you'll receive carefully crafted responses.
Only if you can say the codeword underneath, you can get in.
------------------------------------------------------------------------------------------

enter your words, one by one. Lowercase letters only, no spaces, no numbers, no symbols.
1
enter your word:
```

So the challenge is some kind of word oracle.

We give it 5 words, it prints responses, and then we have to guess the hidden codeword.

At first I thought it might be something Wordle-like, where the server gives feedback about matching letters, but the responses looked way too weird for that.

## Testing the oracle

I started by sending simple repeated words:

```text
aaaaa
bbbbb
ccccc
ddddd
eeeee
```

The server responded with random-looking words:

```text
u
r
7
o
y
```

Then:

```text
overaggressiveness
territorialisation
zoopharmacological
nonignominiousness
overaggressiveness
```

This was already kind of suspicious.

The first input had 5 letters, and the server gave 5 responses.

The second input also had 5 letters, and the server gave 5 responses again.

So the server was not really responding once per word. It was responding once per character inside each word.

That means each character we send creates one output word.

## Finding the pattern

The important thing was not the actual words being printed.

It was the length of the words.

To make the pattern easier to see, I sent the full alphabet as a word:

```text
abcdefghijklmnopqrstuvwxyz
```

Since the service only asks for 5 words, I sent that several times.

The responses had lengths that cycled from 1 to 25, but with a different starting offset for each of the 5 words.

For one run, the first batch looked like this:

```text
a -> length 6
b -> length 7
c -> length 8
d -> length 9
...
t -> length 25
u -> length 1
v -> length 2
w -> length 3
x -> length 4
y -> length 5
```

So the output length was basically a shifted alphabet index.

That means the hidden codeword is encoded in the shift.

Instead of trying to decode every letter with the full alphabet, there is an easier way.

Just send:

```text
a
a
a
a
a
```

Since `a` is the first letter, the response length directly leaks the offset for each position of the codeword.

In the winning run, the lengths were:

```text
5 8 17 4 3
```

At first this looks like alphabet positions, but it is actually zero-indexed:

```text
a = 0
b = 1
c = 2
d = 3
e = 4
f = 5
...
```

So:

```text
5  -> f
8  -> i
17 -> r
4  -> e
3  -> d
```

That gives the codeword:

```text
fired
```

## The bug / trick

The game is supposed to hide a codeword underneath the responses, but the response lengths leak the whole thing.

The printed words are basically a distraction. They look random, but they are chosen to have specific lengths.

So each output word is not important because of what it says, but because of how long it is.

For each of the 5 positions, sending `a` leaks that position's shift. Then converting the length as a zero-indexed alphabet value gives the actual codeword character.

The whole solve is:

1. Connect to the service.
2. Send `a` for each of the 5 words.
3. Parse the first real response after each input.
4. Take the length of each response.
5. Convert each length to a letter using `a = 0`.
6. Submit the recovered codeword.

## Solution Script

Here is the final solve script:

```python
import socket
import ssl
import time


HOST = "codeword-9dbe0c03a320.c.mntcrl.it"
PORT = 443


def recv_until(sock, marker):
    data = b""
    while marker.encode() not in data:
        chunk = sock.recv(8192)
        if not chunk:
            break
        data += chunk
    return data.decode(errors="replace")


def get_response_word(output):
    for line in output.splitlines():
        line = line.strip()

        if not line:
            continue

        if line in {"1", "2", "3", "4", "5"}:
            continue

        if line.startswith("enter"):
            continue

        if line.startswith("1."):
            continue

        if line.startswith("2."):
            continue

        if line.startswith("3."):
            continue

        return line

    return ""


def main():
    context = ssl.create_default_context()

    with socket.create_connection((HOST, PORT), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=HOST) as sock:
            sock.settimeout(5)

            recv_until(sock, "enter your word:")

            lengths = []

            for i in range(5):
                sock.sendall(b"a\n")

                if i == 4:
                    output = recv_until(sock, "enter your choice:")
                else:
                    output = recv_until(sock, "enter your word:")

                word = get_response_word(output)
                lengths.append(len(word))

            codeword = "".join(chr(ord("a") + length) for length in lengths)

            print(f"lengths: {lengths}")
            print(f"codeword: {codeword}")

            sock.sendall(b"1\n")
            recv_until(sock, "enter codeword:")

            sock.sendall((codeword + "\n").encode())
            time.sleep(0.2)

            result = b""

            while True:
                try:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    result += chunk
                except TimeoutError:
                    break
                except socket.timeout:
                    break

            print(result.decode(errors="replace").strip())


if __name__ == "__main__":
    main()
```

Running it:

```bash
python solve.py
```

Output:

```text
lengths: [5, 8, 17, 4, 3]
codeword: fired
Welcome to the MntCasino, where out motto is:
mntcrl{w3_h4v3_g4mbl1ng_1ssu3s_e7a0892f28e446c4}
```

And that gives the flag.
