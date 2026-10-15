# Moto Firmware Downloader (MFD)

[![NPM Version](https://img.shields.io/npm/v/moto-firmware-downloader.svg)](https://www.npmjs.com/package/moto-firmware-downloader)
[![CI](https://github.com/JoshRob297/moto-firmware-downloader/actions/workflows/ci.yml/badge.svg)](https://github.com/JoshRob297/moto-firmware-downloader/actions/workflows/ci.yml)
[![Node Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-blue.svg)](#requirements)

A modern, standalone Node.js CLI tool to authenticate with the Motorola Rescue and Smart Assistant (RSA) API, discover available firmware releases across regional channels, and download official ROM packages directly from high-speed AWS S3 buckets.

This tool bypasses the `410 Missing device fingerprint` and `411 Invalid device fingerprint` errors introduced in the 2024-2026 server security updates by dynamically replicating the RSA encryption implemented in the official Windows client.

---

## Key Features

* **Interactive Guided Wizard:** Run `npx moto-firmware-downloader` without arguments to launch a step-by-step assistant that searches, lists available regional builds, and downloads with one click.
* **Auto OAuth Code Resolution:** Paste the redirect URL or raw authorization code directly; the CLI automatically resolves the final session token.
* **Accelerated Multi-Threaded Downloads:** Uses parallel HTTP `Range: bytes` chunks to maximize bandwidth on high-speed connections.
* **Automated Integrity Verification:** Validates ZIP structural integrity (EOCD/Central Directory) and AWS S3 ETag/MD5 checksums after download.
* **Zero External Dependencies:** Built exclusively with native Node.js standard modules (`crypto`, `readline`, `child_process`, `stream`, `fs`).
* **Built-in Network Doctor:** `mfd doctor` isolates DNS, TCP/TLS, proxy and HTTP layers and surfaces the real transport error code behind Node's generic `fetch failed`.

---

## Requirements
* **Node.js:** v18.0 or higher.
* **Zero Dependencies:** Pure native Node.js implementation.

---

## Quick Start & Installation

### Option A: Run directly with npx (Recommended - No install required)
```bash
# Launch interactive wizard
npx moto-firmware-downloader

# Or run specific commands directly
npx moto-firmware-downloader login
npx moto-firmware-downloader imei XT2415-1 35xxxxxxxxxxxxx --download
```

### Option B: Install globally via npm
```bash
npm install -g moto-firmware-downloader
mfd
```

### Option C: Clone from GitHub
```bash
git clone https://github.com/JoshRob297/moto-firmware-downloader.git
cd moto-firmware-downloader
chmod +x mfd-cli.mjs
npm link
```

---

## Usage

### 1. Interactive Wizard (Recommended)
Simply run `mfd` or `npx moto-firmware-downloader` without parameters:
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
Open the generated link, sign in with your Motorola account, and paste the redirect URL or authorization code into the prompt.

*Tip for headless servers:* Export the token directly via environment variable:
```bash
export MFD_JWT="your_authorization_token_here"
```

#### Lookup & Download Firmware
```bash
mfd imei <Model> <IMEI> [options]
```

**Options:**
* `-c, --carrier <Carrier>`: Target carrier channel (default: `retla`).
* `-d, --download`: Directly download the ROM and Fastboot Tool ZIP files.
* `-o, --output <Directory>`: Specify custom destination folder for downloads.
* `-t, --threads <Number>`: Number of parallel download threads (default: `4`).
* `--json`: Output raw API response in structured JSON format (ideal for CI/automation).
* `--urls-only`: Output only direct, signed AWS S3 download links (one per line) for piping into `curl`, `wget`, or `aria2c`.

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

---

## Technical Details: The Fingerprint Bypass
Motorola servers enforce the `X-Device-Fingerprint` HTTP header. This tool implements the reverse-engineered logic from the official Windows client:
1. Requests the server's public key dynamically from `/common/rsa.jhtml`.
2. Constructs a plaintext string: `Timestamp|JWT_Token|EndpointNameinterface`.
3. Encrypts the string using RSA PKCS#1 v1.5 padding with the server public key and encodes the payload in Base64.

---

## Troubleshooting

### `Network failure connecting to https://lsa.lenovo.com/...: fetch failed`

Since v1.2.5 the CLI prints the real transport error code (`ENOTFOUND`, `ECONNRESET`, `ETIMEDOUT`, TLS errors) instead of the opaque `fetch failed`, and retries transient faults automatically. Run the built-in connectivity doctor first:

```bash
mfd doctor
```

It isolates each layer and reports DNS resolution, TCP/TLS handshake (including the certificate issuer, which exposes TLS interception), proxy state and per-endpoint HTTP status, then states whether the backend is reachable from your machine.

The Lenovo backend answers normally when reached over a clean route. A blanket failure of every request (cookie handshake, RSA key and login dictionary all failing at once) points to the local egress path, not to a service outage:

* **DNS block or filtered resolver:** `nslookup lsa.lenovo.com` returns nothing. Switch DNS resolver, disable VPN split-tunnel or captive portal.
* **TLS interception:** `mfd doctor` shows an unexpected issuer in the certificate chain. Exclude Node.js from the antivirus/proxy HTTPS scanning.
* **Corporate proxy:** export `HTTPS_PROXY=http://host:port`. MFD installs a proxy dispatcher automatically; with Node 24+ you can also start it as `NODE_USE_ENV_PROXY=1 node mfd-cli.mjs`.
* **ISP or regional block:** if the doctor fails at DNS or TCP while the service is confirmed up, retry over a VPN or another network.

### Other issues

* **Authentication Error:** Re-run `mfd login` (or set `export MFD_JWT="..."`).
* **Empty results / ROM not found:** Verify the exact model code (e.g. `XT2415-1` vs `XT2435-1`) and check different carrier channels (`retla`, `reteu`, `retus`, `retbr`).

---

## Credits and Acknowledgments
* **Reverse Engineering & Node.js Implementation:** **JoshRob**
* **Base Architecture & Concept:** [enigma550/LenovoMotoFirmwareDownloader]
* **Community Discussion:** [Official Thread on XDA Forums](https://xdaforums.com/t/tool-cross-platform-moto-firmware-downloader-mfd-v1-1-0-official-s3-roms-rsa-410-411-bypass.4799998/)

---

## License
MIT License. See [LICENSE](LICENSE) for details.
