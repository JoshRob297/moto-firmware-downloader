# Moto Firmware Downloader (MFD)

[![NPM Version](https://img.shields.io/npm/v/moto-firmware-downloader.svg)](https://www.npmjs.com/package/moto-firmware-downloader)
[![CI](https://github.com/JoshRob297/moto-firmware-downloader/actions/workflows/ci.yml/badge.svg)](https://github.com/JoshRob297/moto-firmware-downloader/actions/workflows/ci.yml)
[![Node Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-blue.svg)](#requirements)

A modern, standalone Node.js CLI tool to authenticate with the Motorola Rescue and Smart Assistant (RSA) API and retrieve official firmware download links directly from secure AWS S3 buckets.

This tool bypasses the `410 Missing device fingerprint` and `411 Invalid device fingerprint` errors introduced in the 2024-2026 server security updates by dynamically replicating the RSA encryption implemented in the official Windows client.

---

## Credits and Acknowledgments
* **Concept and Base Architecture:** Based on the foundational work by [enigma550/LenovoMotoFirmwareDownloader].
* **2024 Security Bypass & Reverse Engineering:** Reverse engineering of `webservices.dll`, discovery of the `X-Device-Fingerprint` RSA PKCS#1 v1.5 encryption algorithm, and Node.js implementation by **JoshRob**.
* **Community Discussion:** [Official Thread on XDA Forums](https://xdaforums.com/t/tool-cross-platform-moto-firmware-downloader-mfd-v1-1-0-official-s3-roms-rsa-410-411-bypass.4799998/)

---

## Requirements
* **Node.js:** v18.0 or higher.
* **Zero Dependencies:** Built exclusively with native Node.js standard modules (`crypto`, `readline`, `child_process`, `stream`, `fs`).

---

## Installation

### Option A: Run directly with npx (No install required)
```bash
npx moto-firmware-downloader login
npx moto-firmware-downloader imei <Model> <IMEI>
```

### Option B: Install globally via npm
```bash
npm install -g moto-firmware-downloader
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

### 1. Authentication
The Motorola API requires a valid OAuth session. Run the login command to generate an official authentication link:
```bash
mfd login
# or
node mfd-cli.mjs login
```
1. Open the URL printed in the terminal in your browser.
2. Log in with your Motorola account.
3. When the browser redirects to the success page, copy the full URL from your address bar (or the `Authorization=` token) and paste it into the terminal prompt.

*Alternatively, you can provide the token directly via environment variable without running the login command:*
```bash
export MFD_JWT="your_authorization_token_here"
```

### 2. Download Firmware by IMEI
Retrieve the official factory firmware, fastboot tools, and flash sequence for a specific device using its IMEI:
```bash
mfd imei <Model> <IMEI> [options]
```

**Options:**
* `-c, --carrier <Carrier>`: Target carrier channel (default: `retla`).
* `-d, --download`: Directly download the ROM and Fastboot Tool ZIP files to the current directory with live progress.
* `--json`: Output raw API response in structured JSON format (ideal for automation and scripting).
* `--urls-only`: Output only direct, signed AWS S3 download links (one per line) for piping into `curl`, `wget`, or `aria2c`.

**Examples:**
```bash
# Retail Latin America (default)
mfd imei XT2435-1 351234567890123

# Custom carrier channel (e.g. retus, reteu, retbr)
mfd imei XT2435-1 351234567890123 --carrier reteu

# Direct download with progress bar
mfd imei XT2435-1 351234567890123 --download

# Pipe download URLs directly to aria2c
mfd imei XT2435-1 351234567890123 --urls-only | xargs -n 1 aria2c -x 16
```

### 3. Query Device Match Parameters
Query the specific parameters required by the Motorola backend to match ROMs for a specific model code:
```bash
mfd search <Model> [--json]
```

---

## Technical Details: The Fingerprint Bypass
Motorola servers enforce the `X-Device-Fingerprint` HTTP header. This tool implements the reverse-engineered logic from the official Windows client:
1. Requests the server's public key dynamically from `/common/rsa.jhtml`.
2. Constructs a plain text string: `Timestamp|JWT_Token|EndpointNameinterface`.
3. Encrypts the string using RSA PKCS#1 v1.5 padding with the server public key and encodes the payload in Base64.

---

## Troubleshooting

* **Error: "No active session found" / "Authentication Error"**  
  Run `mfd login` (or set `export MFD_JWT="..."`) to generate or refresh your token.
* **Empty results or "ROM not found"**  
  Verify the exact model code (e.g., `XT2435-1` vs `XT2435-3`) and try specifying the correct carrier channel using `--carrier <name>` (e.g., `retla`, `reteu`, `retus`).

---

## Disclaimer
This project is an independent open-source tool developed for research, device recovery, and unbricking purposes. It is not affiliated with, sponsored by, or endorsed by Motorola Mobility LLC or Lenovo Group Limited.

---

## License
MIT License. See [LICENSE](LICENSE) for details.
