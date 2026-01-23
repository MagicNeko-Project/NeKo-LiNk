#!/bin/bash
# NekoLink Debug Helper
# Stops systemd service, recompiles, and runs locally.

if [ "$EUID" -ne 0 ]; then echo "Please run as root (sudo)"; exit 1; fi

echo ">>> [Debug] Stopping systemd service..."
systemctl stop neko-link

echo ">>> [Debug] Recompiling..."
# Ensure local Go is used if available (make handles this now, but extra check doesn't hurt)
if [ -f ".go/bin/go" ]; then
    export PATH=$PWD/.go/bin:$PATH
fi
make build
if [ $? -ne 0 ]; then echo "❌ Build Failed!"; exit 1; fi

# Detect Config
CONF="/etc/neko-link/config.json" 
# Priority: System config (User Request)
# if [ -f "config.json" ]; then CONF="config.json"; fi
# if [ -f "client_config.json" ]; then CONF="client_config.json"; fi

if [ ! -f "$CONF" ]; then
    echo "❌ No config file found (looked for config.json, client_config.json, /etc/neko-link/config.json)"
    exit 1
fi

echo ">>> [Debug] Starting NekoLink in Foreground (Config: $CONF)..."
echo ">>> (Press Ctrl+C to stop)"
echo "---------------------------------------------------"
./neko-link -c "$CONF"
