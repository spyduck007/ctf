---
title: Right in front of your eyes
date: 2026-07-06
tags:
- web
- LYKNCTF
---

- **Challenge:** Right in front of your eyes
- **Category:** Web
- **Flag:** `LYKNCTF{fd7cd89c3dd740f7b7e15cd4a13db807}`

---

## My initial read / first impressions

The challenge description says:

```text
You just walked right past it without even realizing it existed... or maybe it never did.
```

That already sounds like some kind of browser/history trick. The page itself also leans really hard into that idea:

```text
It in front of your eyes
But you can't see it
```

So my first thought was that the flag was probably not in some complicated endpoint or hidden API. It was probably somewhere I had technically already visited, but the browser was hiding the useful part from me.

Viewing the page source showed this script near the top:

```html
<script>
  // You find 1 more clue hmmm.
  history.replaceState(null, "", "/");
  document.currentScript.remove();
</script>
```

That is the entire challenge basically waving a little flag saying: do not fully trust what the browser is showing you.

## The important clue

The JavaScript does two suspicious things:

```js
history.replaceState(null, "", "/");
document.currentScript.remove();
```

The first line changes the URL in the address bar to `/`. So even if the page originally loaded from some other route, the browser will pretend we are just on the homepage.

The second line removes the script tag from the live DOM. So if I only looked in the Elements tab after the page finished loading, this clue would be gone. That is very on-theme: it existed, but then the page tried to make it look like it never did.

At this point, the move is to stop looking at the rendered page and check the raw HTTP response instead.

## Checking the raw response

I used `curl -i` so I could see the status code, headers, and body without the browser cleaning things up for me:

```bash
curl -i 'http://32aad6c7-d39c-421c-aea8-0aa198cb6dbf.51.79.140.18.nip.io:8080/'
```

That gave:

```http
HTTP/1.1 302 Found
Content-Length: 116
Content-Type: text/plain; charset=utf-8
Date: Mon, 06 Jul 2026 23:51:00 GMT
Location: /e
Server: Python/3.12 aiohttp/3.14.1
```

And the body of the redirect response was the important part:

```text
Well done! You never expect this page to be here, right?
Here is the flag: LYKNCTF{fd7cd89c3dd740f7b7e15cd4a13db807}
```

So the trick is that the useful page is the redirect response itself. A normal browser follows the `302` to `/e`, then the JavaScript on `/e` rewrites the address bar back to `/`, making it feel like nothing weird happened.

But `curl -i` shows the thing that happened in the middle.

## Why this works

A `302 Found` response can still have a response body. Browsers usually do not make that body obvious because they immediately follow the `Location` header.

Here, the server returns the flag in the body of the redirect from `/` to `/e`. Then the page at `/e` uses:

```js
history.replaceState(null, "", "/");
```

to hide the fact that `/e` was involved at all.

So the solve is just to inspect the HTTP layer directly instead of only trusting the browser UI.

## Solution

The full solve is literally:

```bash
curl -i 'http://32aad6c7-d39c-421c-aea8-0aa198cb6dbf.51.79.140.18.nip.io:8080/'
```

The flag is in the body of the `302 Found` response.

## Flag

```text
LYKNCTF{fd7cd89c3dd740f7b7e15cd4a13db807}
```
