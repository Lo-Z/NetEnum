#!/bin/bash
set -e

# Define installation directories and filenames
BIN_DIR="/usr/local/bin"
DESKTOP_DIR="/usr/share/applications"
ICON_DIR="/usr/share/icons/hicolor/256x256/apps"

EXECUTABLE="NetEnum_2.0"
DESKTOP_FILE="NetEnum_2.0.desktop"
ICON_FILE="NetEnum_Logo.png"

# Check if running as root; if not, exit.
if [[ $EUID -ne 0 ]]; then
    echo "This installer requires root privileges. Please run with sudo."
    exit 1
fi

echo "Installing ${EXECUTABLE} to ${BIN_DIR}..."
cp -r "./dist/${EXECUTABLE}" "${BIN_DIR}/${EXECUTABLE}"
chmod +x "${BIN_DIR}/${EXECUTABLE}/${EXECUTABLE}"

echo "Installing desktop entry to ${DESKTOP_DIR}..."
cp "./${DESKTOP_FILE}" "${DESKTOP_DIR}/"

echo "Installing icon to ${ICON_DIR}..."
mkdir -p "${ICON_DIR}"
cp "./${ICON_FILE}" "${ICON_DIR}/"

# Update desktop entry with correct paths
sed -i "s|^Exec=.*|Exec=${BIN_DIR}/${EXECUTABLE}/${EXECUTABLE}|g" "${DESKTOP_DIR}/${DESKTOP_FILE}"
sed -i "s|^Icon=.*|Icon=${ICON_DIR}/${ICON_FILE}|g" "${DESKTOP_DIR}/${DESKTOP_FILE}"

# Optional desktop shortcut for user
if [ -n "$SUDO_USER" ]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    USER_DESKTOP="$USER_HOME/Desktop"
    if [ -d "$USER_DESKTOP" ]; then
        echo "Creating desktop shortcut in $USER_DESKTOP..."
        cp "${DESKTOP_DIR}/${DESKTOP_FILE}" "$USER_DESKTOP/"
        chown "$SUDO_USER":"$SUDO_USER" "$USER_DESKTOP/${DESKTOP_FILE}"
    fi
fi

echo "Installation complete!"