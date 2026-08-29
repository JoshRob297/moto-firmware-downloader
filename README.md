# Moto Firmware Downloader (MFD)

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

---

## Requirements
* **Node.js:** v18.0 or higher.
* **Zero Dependencies:** Built exclusively with native Node.js built-ins (`crypto`, `readline`, `child_process`, `fs`).

---

## Installation

Clone the repository and mark the script as executable:
```bash
git clone https://github.com/JoshRob297/moto-firmware-downloader.git
cd moto-firmware-downloader
chmod +x mfd-cli.mjs
```

*(Optional)* Install globally to use the `mfd` command from anywhere on your system:
```bash
npm link
```

---

## Usage

### 1. Authentication
The Motorola API requires a valid OAuth session. Run the login command to generate an official authentication link:
```bash
node mfd-cli.mjs login
# or if installed globally:
mfd login
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
node mfd-cli.mjs imei <Model> <IMEI> [--carrier <Carrier>]
```

**Examples:**
```bash
# Retail Latin America (default)
node mfd-cli.mjs imei XT2435-1 351234567890123

# Custom carrier channel (e.g. retus, reteu, retbr)
node mfd-cli.mjs imei XT2435-1 351234567890123 --carrier reteu
```

The tool outputs direct, signed AWS S3 download links for the full ROM package and flash tools.

### 3. Query Device Match Parameters
Query the specific parameters required by the Motorola backend to match ROMs for a specific model code:
```bash
node mfd-cli.mjs search <Model>
```

---

## Technical Details: The Fingerprint Bypass
Motorola servers enforce the `X-Device-Fingerprint` HTTP header. This tool implements the reverse-engineered logic from the official Windows client:
1. Requests the server's public key dynamically from `/common/rsa.jhtml`.
2. Constructs a plain text string: `Timestamp|JWT_Token|EndpointNameinterface`.
3. Encrypts the string using RSA PKCS#1 v1.5 padding with the server public key and encodes the payload in Base64.

---

## Troubleshooting

- **Error: "No active session found"**  
  Run `node mfd-cli.mjs login` or set `export MFD_JWT="..."` before executing queries.
- **Empty results or "ROM not found"**  
  Verify the exact model code (e.g., `XT2435-1` vs `XT2435-3`) and try specifying the correct carrier channel using `--carrier <name>` (e.g., `retla`, `reteu`, `retus`).
- **Authorization Token Expiration**  
  Motorola OAuth tokens have a rolling expiration. If requests start failing, simply re-run `node mfd-cli.mjs login` to renew your session.

---

## Disclaimer
This project is an independent open-source tool developed for research, device recovery, and unbricking purposes. It is not affiliated with, sponsored by, or endorsed by Motorola Mobility LLC or Lenovo Group Limited.

---

## License
MIT License. See [LICENSE](LICENSE) for details.
