#!/bin/bash
# Install Explosive V3.1.0 binaries

BIN_DIR="$HOME/explosive"
mkdir -p "$BIN_DIR"

cp ledgerapp walletapp "$BIN_DIR/"
chmod +x "$BIN_DIR/ledgerapp" "$BIN_DIR/walletapp"

echo "Explosive V3.1.0 installed in $BIN_DIR"
