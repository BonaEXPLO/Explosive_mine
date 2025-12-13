#!/bin/bash
set -e

echo "Installing EXPLOSIVE Network V3.1..."

cp ledgerapp /usr/local/bin/ledgerapp
chmod +x /usr/local/bin/ledgerapp

cp walletapp /usr/local/bin/walletapp
chmod +x /usr/local/bin/walletapp

echo "Installation complete!"
