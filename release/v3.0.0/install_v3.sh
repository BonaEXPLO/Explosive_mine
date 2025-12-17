#!/usr/bin/env bash
set -euo pipefail

BASE="https://github.com/BonaEXPLO/Explosive_mine/releases/download/v3.0.0"
DEST="$HOME/explosive"
mkdir -p "$DEST"
cd "$DEST"

echo "Downloading files..."
wget -q -O ledgerapp "${BASE}/ledgerapp"
wget -q -O walletapp "${BASE}/walletapp"
wget -q -O p2pnode "${BASE}/p2pnode"
wget -q -O release-checksums.txt "${BASE}/release-checksums.txt"

echo "Verifying checksums..."
sha256sum -c release-checksums.txt

chmod +x ledgerapp walletapp p2pnode

echo "Install OK — run ./p2pnode, ./ledgerapp, ./walletapp as needed."
