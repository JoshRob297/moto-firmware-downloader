# Contributing to Moto Firmware Downloader

Thank you for your interest in contributing!

## How to Contribute

1. **Reporting Bugs:**
   - Use the [Bug Report issue template](https://github.com/JoshRob297/moto-firmware-downloader/issues/new?template=bug_report.md).
   - **Never share sensitive data** such as personal IMEIs, serial numbers, or full JWT authentication tokens in public issues.

2. **Feature Requests:**
   - Open a feature request discussing the proposal.

3. **Submitting Pull Requests (PRs):**
   - Fork the repository.
   - Keep changes focused and minimal.
   - Ensure the project maintains **zero third-party runtime dependencies** (use native Node.js built-ins).
   - Verify code passes syntax and tests:
     ```bash
     npm test
     ```
   - Submit PR targeting `main`.

## Code Style & Philosophy
- Pure vanilla modern ES Modules (`.mjs`).
- Clean, self-documenting code without unnecessary abstractions.
- Cross-platform compatibility (Linux, macOS, Windows).
