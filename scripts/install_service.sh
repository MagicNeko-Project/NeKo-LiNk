#!/bin/bash
set -e

SERVICE_NAME="neko-link.service"
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"
SOURCE_PATH="$(dirname "$0")/../neko-link.service"

echo ">>> Installing Neko-Link Systemd Service... 🐾"

if [ ! -f "$SOURCE_PATH" ]; then
    echo "Error: Service file not found at $SOURCE_PATH"
    exit 1
fi

echo "Copying service file to $SERVICE_PATH..."
cp "$SOURCE_PATH" "$SERVICE_PATH"

echo "Reloading systemd daemon..."
systemctl daemon-reload

echo "Enabling service..."
systemctl enable $SERVICE_NAME

echo "Restarting service..."
systemctl restart $SERVICE_NAME

echo "Check status:"
systemctl status $SERVICE_NAME --no-pager

echo ">>> Systemd setup complete! 喵! 🐾"
