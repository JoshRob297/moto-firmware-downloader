# Moto Firmware Downloader (MFD)

[![Latest Release](https://img.shields.io/github/v/release/JoshRob297/moto-firmware-downloader.svg)](https://github.com/JoshRob297/moto-firmware-downloader/releases/latest)
[![CI](https://github.com/JoshRob297/moto-firmware-downloader/actions/workflows/ci.yml/badge.svg)](https://github.com/JoshRob297/moto-firmware-downloader/actions/workflows/ci.yml)
[![Node Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-blue.svg)](#requirements)

A modern, standalone Node.js CLI tool to authenticate with the Motorola Rescue and Smart Assistant (RSA) API, discover available firmware releases across regional channels, and download official ROM packages directly from high-speed AWS S3 buckets.

This tool bypasses the `410 Missing device fingerprint` and `411 Invalid device fingerprint` errors introduced in the 2024-2026 server security updates by dynamically replicating the RSA encryption implemented in the official Windows client.

---

## Distribution Policy

**MFD is distributed exclusively through GitHub since v1.3.0.** There is no npm registry publication: no account, no tokens, no renewal, and no third-party registry in the supply chain. Every release ships the exact `mfd-cli.mjs` artifact as a GitHub Release asset together with the installers, so what you run is what the repository contains.

Older versions (`<= 1.2.4`) remain on the npm registry as frozen artifacts. They are not maintained and no longer match the current codebase.

---

## Key Features

* **Interactive Guided Wizard:** Run `mfd` without arguments to launch a step-by-step assistant that searches, lists available regional builds, and downloads with one click.
* **IMEI or Serial Lookup:** Cellular devices are looked up by IMEI, WiFi-only tablets by serial number, mirroring the endpoint the official client uses for each case. See [`docs/DEVICE-IDENTIFIERS.md`](docs/DEVICE-IDENTIFIERS.md).
* **Guided Token Capture:** The login prompt prints the exact steps to grab the session token from the browser (console or Network tab). Both the JWT and the 32-character token formats are accepted. See [`docs/AUTHENTICATION.md`](docs/AUTHENTICATION.md).
* **Accelerated Multi-Threaded Downloads:** Uses parallel HTTP `Range: bytes` chunks to maximize bandwidth on high-speed connections.
* **Automated Integrity Verification:** Validates ZIP structural integrity (EOCD/Central Directory) and AWS S3 ETag/MD5 checksums after download.
* **Built-in Network Doctor:** `mfd doctor` isolates DNS, TCP/TLS, proxy and HTTP layers and surfaces the real transport error code behind Node's generic `fetch failed`.
* **Zero External Dependencies:** Built exclusively with native Node.js standard modules (`crypto`, `readline`, `child_process`, `stream`, `fs`).

---

## Requirements
* **Node.js:** v18.0 or higher.
* **Zero Dependencies:** Pure native Node.js implementation.

---

## Installation

### Option A: One-line installer (Recommended)

Linux and macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/JoshRob297/moto-firmware-downloader/main/install.sh | bash
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/JoshRob297/moto-firmware-downloader/main/install.ps1 | iex
```

The installer validates the Node version, checks the script syntax, places `mfd` in `~/.local/bin` (or `%LOCALAPPDATA%\mfd` on Windows) and reports the PATH entry when one is needed. Override the target with `MFD_DEST=/usr/local/bin`, or install a specific revision with `MFD_REF=v1.3.0`.

### Option B: Manual download from the latest release

```bash
curl -fsSL -O https://github.com/JoshRob297/moto-firmware-downloader/releases/latest/download/mfd-cli.mjs
chmod +x mfd-cli.mjs
./mfd-cli.mjs --version
```

### Option C: Clone the repository

```bash
git clone https://github.com/JoshRob297/moto-firmware-downloader.git
cd moto-firmware-downloader
chmod +x mfd-cli.mjs
./mfd-cli.mjs --help
```

Optional, to expose the `mfd` command locally without any registry involved:

```bash
npm link        # local symlink only, never touches a registry
```

---

## Usage

### 1. Interactive Wizard (Recommended)
Simply run `mfd` without parameters:
```bash
mfd
```
The wizard will:
1. Verify / initiate your Motorola login session.
2. Prompt for your device Model and IMEI.
3. Query the Motorola catalog across multiple regional software channels (`retla`, `reteu`, `retus`, `retbr`, etc.).
4. Present a numbered menu of all available firmware releases with build names, dates, and file sizes.
5. Download the selected firmware using multi-threaded acceleration and verify its integrity.

---

### 2. Manual CLI Mode (Advanced & Scripting)

#### Authenticate
```bash
mfd login
```

1. Open the fresh URL the CLI prints and sign in with your Motorola / Lenovo account.
2. Capture the session token the browser hands to the desktop client:
   * **Console:** `F12` → Console → look for `Prevented navigation to "softwareFix://authcallback?...Authorization=eyJ..."`.
   * **Network (most reliable):** `F12` → Network → filter `callback.jhtml` → Response → copy the `Authorization` value.
3. Paste the whole URI or just the token into the prompt.

Both token formats work: the JWT (`eyJ...`) from `softwareFix://authcallback` and the 32-character value from `softwarefix://callback`. Tokens are short-lived, so paste immediately. Do **not** paste the `code=` from the `lenovoIdSuccess.html` redirect URL - the browser consumes that one-time code before you can reuse it.

Non-interactive alternatives, useful when a terminal mangles pasted input (Windows console, tmux, SSH):

```bash
mfd login --token "<token>"              # validate and save directly
mfd login --token-file ~/token.txt       # read the token from a file
Get-Clipboard | mfd login --stdin        # Windows PowerShell: pipe the clipboard
```

Full procedure, response-code table and troubleshooting: [`docs/AUTHENTICATION.md`](docs/AUTHENTICATION.md).

*Tip for headless servers:* Export the token directly via environment variable:
```bash
export MFD_JWT="your_authorization_token_here"
```

#### Lookup & Download Firmware
```bash
mfd imei <Model> <IMEI|Serial> [options]
```

Pass an IMEI (`14-15` digits) for cellular devices or a serial number for WiFi-only tablets; the identifier type is detected automatically, or forced with `--serial`.

**Options:**
* `-c, --carrier <Carrier>`: Target carrier channel (default: `retla`).
* `-d, --download`: Directly download the ROM and Fastboot Tool ZIP files.
* `-o, --output <Directory>`: Specify custom destination folder for downloads.
* `-t, --threads <Number>`: Number of parallel download threads (default: `4`).
* `--json`: Output raw API response in structured JSON format (ideal for CI/automation).
* `--urls-only`: Output only direct, signed AWS S3 download links (one per line) for piping into `curl`, `wget`, or `aria2c`.
* `--serial`: Treat the identifier as a device serial number instead of an IMEI.

**Examples:**
```bash
# Retail Latin America (default)
mfd imei XT2435-1 351234567890123

# Custom carrier channel with 8 parallel download threads
mfd imei XT2415-1 351234567890123 --carrier reteu --download -t 8 -o ./firmwares

# Pipe direct S3 download URLs to aria2c
mfd imei XT2435-1 351234567890123 --urls-only | xargs -n 1 aria2c -x 16
```

#### Query Device Match Parameters
```bash
mfd search <Model> [--json]
```

#### Diagnose Connectivity
```bash
mfd doctor [--json]
```
Reports DNS resolution, TCP/TLS handshake and certificate issuer, proxy state and per-endpoint HTTP status, then states whether the Lenovo backend is reachable from your machine.

---

## Technical Details: The Fingerprint Bypass
Motorola servers enforce the `X-Device-Fingerprint` HTTP header. This tool implements the reverse-engineered logic from the official Windows client:
1. Requests the server's public key dynamically from `/common/rsa.jhtml`.
2. Constructs a plaintext string: `Timestamp|JWT_Token|EndpointNameinterface`.
3. Encrypts the string using RSA PKCS#1 v1.5 padding with the server public key and encodes the payload in Base64.

---

## Troubleshooting

### `Backend Validation Failed` during `mfd login`

Since v1.3.1 the login probe reports the endpoint it called, the verbatim server response, the raw body and the proxy state, and it validates against the same catalog endpoint the commands use. Read the response code:

| Observed | Meaning | Action |
|---|---|---|
| `403 Invalid token.` | The token is not (or no longer) valid. | Generate a fresh session with `N` and paste immediately |
| `410 Missing device fingerprint.` | The RSA key was not fetched before the call. | Check that `mfd doctor` shows the RSA probe as LMSA `0000` |
| `412 Fingerprint expired.` | Clock skew on the machine. | Sync the system clock and retry |
| `unexpected non-LMSA response (HTTP 404 ...)` | Something other than the Lenovo API answered. | A proxy, VPN, captive portal or antivirus HTTPS inspection is rewriting responses; run `mfd doctor` |

**Which value to paste.** Both token formats the LMSA flow offers work and are accepted by the backend:

* `softwareFix://authcallback?Authorization=eyJ...` (JWT, from the browser prompt or console).
* `softwarefix://callback?fullName=...&Authorization=<32 hex characters>`.

Paste the whole URI or just the token value. These tokens are short-lived: an old or already-used token answers `403 Invalid token.`, so paste immediately after logging in.

Do not paste the `code=...` parameter from the `lenovoIdSuccess.html` redirect URL: the browser's success page consumes that one-time code, and a second exchange answers `oauth2 state not found`.

### `Network failure connecting to https://lsa.lenovo.com/...: fetch failed`

Since v1.2.5 the CLI prints the real transport error code (`ENOTFOUND`, `ECONNRESET`, `ETIMEDOUT`, TLS errors) instead of the opaque `fetch failed`, and retries transient faults automatically. Run the built-in connectivity doctor first:

```bash
mfd doctor
```

It isolates each layer and reports DNS resolution, TCP/TLS handshake (including the certificate issuer, which exposes TLS interception), proxy state and per-endpoint HTTP status, then states whether the backend is reachable from your machine. A healthy run looks like this:

```text
[OK]   HTTP 302 cookie handshake (GET)
[OK]   HTTP 200 RSA public key (POST) (LMSA code 0000: ...)
[OK]   HTTP 200 login URL dictionary (POST) (LMSA code 0000: success)
[OK]   HTTP 200 catalog endpoint gated (POST) (LMSA code 410: Missing device fingerprint.)
```

The catalog probe is expected to answer `410 Missing device fingerprint.` before you log in: that proves the API edge is serving the tool and not a middlebox. An HTML `404` or any body without LMSA fields means something in your network is answering on behalf of Lenovo. An unexpected certificate issuer means TLS interception.

The Lenovo backend answers normally when reached over a clean route. A blanket failure of every request (cookie handshake, RSA key and login dictionary all failing at once) points to the local egress path, not to a service outage:

* **DNS block or filtered resolver:** `nslookup lsa.lenovo.com` returns nothing. Switch DNS resolver, disable VPN split-tunnel or captive portal.
* **TLS interception:** `mfd doctor` shows an unexpected issuer in the certificate chain. Exclude Node.js from the antivirus/proxy HTTPS scanning.
* **Corporate proxy:** export `HTTPS_PROXY=http://host:port`. MFD installs a proxy dispatcher automatically; with Node 24+ you can also start it as `NODE_USE_ENV_PROXY=1 node mfd-cli.mjs`.
* **ISP or regional block:** if the doctor fails at DNS or TCP while the service is confirmed up, retry over a VPN or another network.

### The login URL does not open in a browser

`mfd login` tries to open the URL automatically. On Windows it uses `rundll32 url.dll,FileProtocolHandler`; `explorer.exe` is deliberately avoided because it treats the URL as a path and opens your Documents folder instead. If nothing opens, the URL is always printed in full: copy it manually.

To force a specific browser or command:

```bash
MFD_BROWSER="firefox --new-window" mfd login     # Linux / macOS
$env:MFD_BROWSER="C:\path\to\browser.exe"; mfd login   # Windows PowerShell
```

### Other issues

* **Browser opens a login page that errors out (Windows):** fixed in v1.3.1. Older builds launched the browser through `cmd.exe /c start`, which truncates OAuth URLs at the first `&`, so the page opened with only `?state=...`. The CLI now hands the full URL to `explorer.exe`. The console always printed the correct URL, so pasting it manually was the workaround.
* **Command not found after installing:** the installer prints the PATH entry to add; restart the terminal afterwards on Windows.
* **Authentication Error:** Re-run `mfd login` (or set `export MFD_JWT="..."`).
* **Empty results / ROM not found:** Verify the exact model code (e.g. `XT2415-1` vs `XT2435-1`) and check different carrier channels (`retla`, `reteu`, `retus`, `retbr`). MFD prints the last catalog response (endpoint, code, `content` shape) so you can see whether the API returned nothing or returned a build without a download resource. See [`docs/DEVICE-IDENTIFIERS.md`](docs/DEVICE-IDENTIFIERS.md).
* **Duplicate entries in the firmware list:** MFD collapses builds that differ only by S3 signature. If two entries still look identical, the carrier line distinguishes them (the list shows the queried carrier when it differs from the reported one).
* **Running an old copy:** verify with `mfd --version` and re-run the installer to move to the latest release.

---

## Credits and Acknowledgments
* **Reverse Engineering & Node.js Implementation:** **JoshRob**
* **Base Architecture & Concept:** [enigma550/LenovoMotoFirmwareDownloader]
* **Community Discussion:** [Official Thread on XDA Forums](https://xdaforums.com/t/tool-cross-platform-moto-firmware-downloader-mfd-v1-1-0-official-s3-roms-rsa-410-411-bypass.4799998/)

---

## License
MIT License. See [LICENSE](LICENSE) for details.
