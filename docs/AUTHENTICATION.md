# MFD Authentication: obtaining and using a session token

Everything below was verified against the live Lenovo/LMSA backend. Response codes and
behaviours are measured, not inferred.

---

## 1. Run the login flow

```bash
mfd login
```

The CLI prints a fresh authorization URL, for example:

```text
https://passport-glb.lenovo.com/v1.0/utility/lenovoid/oauth2/authorize?state=...&client_id=...&response_type=code&redirect_uri=...&scope=openid&code_challenge=...&code_challenge_method=S256
```

Open it and sign in with your Motorola / Lenovo account. The CLI also tries to open your
default browser automatically. Tokens are short-lived, so complete steps 2 and 3
immediately after signing in.

---

## 2. Capture the token

Three methods, all equivalent. Use whichever your browser allows.

### Method A - browser prompt (fastest)

After signing in, the success page tries to hand off to the desktop client, so your
browser shows a prompt to open an external application (`Software Fix`) or a warning
that navigation to an unknown protocol was prevented:

```text
softwareFix://authcallback?Authorization=eyJhbGciOi...
```

Copy that URI and paste the **whole thing** into the CLI. The token is the value after
`Authorization=`.

### Method B - DevTools Console

Press `F12`, open the **Console** tab and look for an entry such as:

```text
Prevented navigation to "softwareFix://authcallback?...Authorization=eyJ..."
```

Copy the URI or just the token value and paste it into the CLI.

### Method C - DevTools Network tab (most reliable)

Use this when the browser silently swallows the custom-scheme prompt.

1. Press `F12` and open the **Network** tab before signing in so the request is recorded.
2. Sign in.
3. Filter the requests for `callback.jhtml`.
4. Open that request and switch to the **Response** tab.
5. The response body contains the handoff URI. Copy the `Authorization` value:

```text
softwareFix://authcallback?Authorization=eyJhbGciOi...
```

Paste it into the CLI. The CLI validates it against the live backend and saves the
session to `~/.mfd-cli-state.json` (mode `0600`).

---

## 3. Accepted token formats

Both formats are valid session tokens and both were confirmed against the live catalog
endpoint:

| Format | Where it comes from | Example |
|---|---|---|
| JWT (3 dot-separated segments) | `softwareFix://authcallback?Authorization=` (methods A/B/C) | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig` |
| 32 hex characters | `softwarefix://callback?fullName=...&Authorization=` | `d661434a5aef446db5aa6f104297f0a3` |

Verified response for a freshly issued 32-hex token:

```http
POST /Interface/rescueDevice/getRomMatchParams.jhtml
HTTP 200 {"code":"0000","desc":"Request success","content":{"modelName":"XT2435-1","platform":"MTK","params":[...]}}
```

The same request succeeds with **no cookies at all**, so the session is not bound to the
browser session cookie. Pasting only the token is enough.

You may paste the full URI or just the token value; the CLI extracts it either way.
A `Bearer ` prefix is also stripped automatically.

---

## 4. What does NOT work

**Do not paste the `code=` parameter from the redirect URL.** After signing in, the
browser lands on:

```text
https://lsa.lenovo.com/Tips/lenovoIdSuccess.html?code=fc167cd9...&scope=openid&state=...
```

The page's own JavaScript consumes that one-time code immediately, so any later exchange
is rejected. Measured result of retrying the exchange:

```http
GET /Interface/user/oauth2/callback.jhtml?code=<code>&state=<state>&scope=openid
HTTP 200 {"code":"1000","desc":"softwareFix://callback?error=oauth2 state not found.","content":null}
```

This is a protocol property, not a tool limitation you can work around by pasting faster.
Use a token (section 3) instead.

**Old tokens do not work.** A token that was already used, or that has expired, answers
`403 Invalid token.` Generate a fresh session with `N` at the login prompt.

---

## 5. Backend response codes

These are the LMSA codes the CLI reports. They are returned as `HTTP 200` with a JSON
body unless noted.

| Code | `desc` | Meaning | Action |
|---|---|---|---|
| `0000` | `Request success` | Authenticated and processed | none |
| `1000` | `Request error` / `failure` | Authenticated, request rejected (e.g. unknown model or IMEI) | check the model/IMEI value |
| `403` | `Invalid token.` | No session, or expired/used token | log in again and paste immediately |
| `410` | `Missing device fingerprint.` | `X-Device-Fingerprint` header absent | expected before login; if seen after login, the RSA key fetch failed |
| `411` | `Invalid device fingerprint.` | Fingerprint malformed | do not patch the header manually; run `mfd doctor` |
| `412` | `Fingerprint expired.` | Clock skew on the machine | sync the system clock |

### The authenticated-404 trap

A path that does not exist under `/Interface` behaves differently depending on whether the
request is authenticated:

| Request | Response |
|---|---|
| Nonexistent path, unauthenticated | `HTTP 200 {"code":"403","desc":"Invalid token."}` |
| Nonexistent path, **valid token** | `HTTP 404 {"timestamp":...,"status":404,"error":"Not Found","path":"..."}` |
| Real endpoint (`getRomMatchParams.jhtml`), valid token | `HTTP 200 {"code":"0000","desc":"Request success"}` |

Because the auth gate answers `403` before routing, a nonexistent path looks like "bad
token" while unauthenticated, and only reveals itself as `404` **after** the token is
accepted. A `404` with a Spring `{"timestamp","status","error","path"}` body is therefore
never an authentication failure: it means the token was accepted and the path is wrong.

This is exactly what happened between v1.2.2 and v1.3.0: the validator probed
`/Interface/query/matchParams.jhtml`, which does not exist, so valid tokens were reported
as `Invalid token or expired session (Code: 404)`. Fixed in v1.3.1; the misleading wording
was corrected in v1.3.2. If you are on an older build and see `Code: 404`, update:

```bash
curl -fsSL https://raw.githubusercontent.com/JoshRob297/moto-firmware-downloader/main/install.sh | bash
```

---

## 6. Verifying a session

```bash
# Catalog parameters for a model (requires a session)
mfd search XT2435-1 --json

# Full lookup
mfd imei XT2435-1 <IMEI> --carrier retla
```

A working session returns catalog data. `403 Invalid token.` means the session expired;
`mfd login` again.

---

## 7. Reducing credentials exposure

* The session is stored in `~/.mfd-cli-state.json` with mode `0600`.
* Never paste a token into a public issue, gist or CI log; treat it as a password.
* For headless use, inject it at runtime instead of storing it:
  `export MFD_JWT="<token>" mfd search XT2435-1 --json`
* Remove a stored session with `rm ~/.mfd-cli-state.json`.
