# Moto Firmware Downloader (MFD)

A modern, standalone Node.js CLI tool to authenticate with the Motorola Rescue and Smart Assistant (RSA) API and retrieve official firmware download links directly from secure AWS S3 buckets.

This tool bypasses the `410 Missing device fingerprint` and `411 Invalid device fingerprint` errors introduced in the 2024-2026 server security updates by dynamically replicating the RSA encryption implemented in the official Windows client.

## Credits and Acknowledgments
* **Concept and Base Architecture:** Based on the foundational work by [enigma550/LenovoMotoFirmwareDownloader].
* **2024 Security Bypass & Reverse Engineering:** Reverse engineering of the `webservices.dll`, discovery of the `X-Device-Fingerprint` RSA PKCS#1 v1.5 encryption algorithm, and Node.js implementation by **JoshRob**.

## Requirements
* Node.js v18.0 or higher.
* No third-party npm packages required (pure native implementation using Node.js `crypto`, `http`, and `fs` modules).

## Usage

### 1. Authentication
The Motorola API requires a valid OAuth session. Run the login command to generate a local callback server and an official authentication link:
```bash
node mfd-cli.mjs login
```
Open the provided URL in your browser, log in with your Motorola account, and the script will automatically capture the session token and the server's daily RSA public key.

### 2. Download Firmware by IMEI
Retrieve the official factory firmware, fastboot tools, and flash sequence for a specific device using its IMEI:
```bash
node mfd-cli.mjs imei <Model> <IMEI>
```

**Example:**
```bash
node mfd-cli.mjs imei XT2435-1 351234567890123
```

The tool will output the direct, signed AWS S3 download links for the full ROM package and flash tools.

### 3. Query Device Match Parameters
Query the specific parameters required by the Motorola backend to match ROMs for a specific model code:
```bash
node mfd-cli.mjs search <Model>
```

## Technical Details: The Fingerprint Bypass
Motorola servers enforce the `X-Device-Fingerprint` HTTP header. This tool implements the reverse-engineered logic from the official Windows client:
1. Requests the server's public key dynamically from `/common/rsa.jhtml`.
2. Constructs a plain text string: `Timestamp|JWT_Token|EndpointNameinterface`.
3. Encrypts the string using RSA PKCS#1 v1.5 padding with the server public key and encodes the payload in Base64.
