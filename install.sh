#!/bin/bash

# FluxMonitorQT Install Script
# Installs the desktop entry and builds the release binary

set -e

echo "Compiling release build..."
# Force Qt5 and build optimized release
QMAKE=qmake-qt5 cargo build --release

# Get absolute path to the release binary
BIN_PATH="$(pwd)/target/release/flux_monitor_qt"
ICON_PATH="$(pwd)/screenshot.png" # Ideally we'd have a logo.png, using screenshot/system icon for now
DESKTOP_FILE="flux_monitor_qt.desktop"

if [ ! -f "$BIN_PATH" ]; then
    echo "Error: Build failed or binary not found at $BIN_PATH"
    exit 1
fi

echo "Creating desktop entry..."
# We create a temporary desktop file with the absolute path
cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Name=FluxMonitorQT
Comment=Network Connection Monitor
Exec=$BIN_PATH
Icon=utilities-system-monitor
Terminal=false
Type=Application
Categories=System;Monitor;Network;
Keywords=network;monitor;traffic;rust;qt;
EOF

# Install to user applications directory
INSTALL_DIR="$HOME/.local/share/applications"
mkdir -p "$INSTALL_DIR"
cp "$DESKTOP_FILE" "$INSTALL_DIR/"

# Make the desktop file executable just in case
chmod +x "$INSTALL_DIR/$DESKTOP_FILE"

echo "✅ Installation complete!"
echo "FluxMonitorQT should now appear in your system application menu."
echo "You can launch it from there."
