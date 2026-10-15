#!/usr/bin/env bash
#
# Moto Firmware Downloader (MFD) installer.
# GitHub-only distribution: no npm registry, no tokens involved.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/JoshRob297/moto-firmware-downloader/main/install.sh | bash
#
# Environment overrides:
#   MFD_DEST=/usr/local/bin          install directory (default: ~/.local/bin)
#   MFD_REF=main                     install from a git ref instead of the latest release
#   MFD_SOURCE=/path/to/mfd-cli.mjs  install from a local file
#
set -euo pipefail

REPO="JoshRob297/moto-firmware-downloader"
BIN_NAME="mfd"
DEST_DIR="${MFD_DEST:-$HOME/.local/bin}"

command -v node >/dev/null 2>&1 || {
  echo "[!] Node.js 18 or newer is required. Install it from https://nodejs.org" >&2
  exit 1
}

node -e '
const major = Number(process.versions.node.split(".")[0]);
if (major < 18) {
  console.error(`[!] Node.js 18 or newer is required, found ${process.version}`);
  process.exit(1);
}
'

if [ -n "${MFD_SOURCE:-}" ]; then
  SOURCE_DESC="local file $MFD_SOURCE"
  URLS=""
elif [ -n "${MFD_REF:-}" ]; then
  SOURCE_DESC="git ref $MFD_REF"
  URLS="https://raw.githubusercontent.com/$REPO/$MFD_REF/mfd-cli.mjs"
else
  SOURCE_DESC="latest release (fallback: main branch)"
  URLS="https://github.com/$REPO/releases/latest/download/mfd-cli.mjs
https://raw.githubusercontent.com/$REPO/main/mfd-cli.mjs"
fi

TMP_DIR="$(mktemp -d)"
TMP_FILE="$TMP_DIR/mfd-cli.mjs"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "[*] Fetching mfd-cli.mjs ($SOURCE_DESC)..."

fetch_to() {
  local source_url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$source_url" -o "$TMP_FILE"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TMP_FILE" "$source_url"
  else
    echo "[!] Neither curl nor wget is available." >&2
    return 1
  fi
}

if [ -n "${MFD_SOURCE:-}" ]; then
  cp "$MFD_SOURCE" "$TMP_FILE"
else
  FETCHED=0
  while IFS= read -r candidate; do
    [ -n "$candidate" ] || continue
    if fetch_to "$candidate"; then
      FETCHED=1
      break
    fi
    echo "[!] Could not fetch $candidate"
  done <<< "$URLS"

  if [ "$FETCHED" -ne 1 ]; then
    echo "[!] All download sources failed. Check your network path with 'mfd doctor'." >&2
    exit 1
  fi
fi

if [ ! -s "$TMP_FILE" ]; then
  echo "[!] Downloaded file is empty. Check the ref or your network path." >&2
  exit 1
fi

node --check "$TMP_FILE"

mkdir -p "$DEST_DIR"
if command -v install >/dev/null 2>&1; then
  install -m 0755 "$TMP_FILE" "$DEST_DIR/$BIN_NAME"
else
  cp "$TMP_FILE" "$DEST_DIR/$BIN_NAME"
  chmod 0755 "$DEST_DIR/$BIN_NAME"
fi

echo "[+] Installed $BIN_NAME -> $DEST_DIR/$BIN_NAME"

case ":${PATH}:" in
  *":$DEST_DIR:"*) ;;
  *)
    echo "[!] $DEST_DIR is not in PATH. Add it with:"
    echo "    export PATH=\"$DEST_DIR:\$PATH\""
    ;;
esac

"$DEST_DIR/$BIN_NAME" --version || true
