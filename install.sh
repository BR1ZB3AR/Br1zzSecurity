#!/usr/bin/env bash
#
# Br1zz Security installer.
#
# Installs entirely into the current user's home directory - no root, no files
# outside $HOME. The one thing it cannot do unprivileged is install the YARA
# bindings; it tells you the command instead of running sudo behind your back.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$HOME/.local/bin"
APP_DIR="$HOME/.local/share/applications"
UNIT_DIR="$HOME/.config/systemd/user"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }

echo
bold "Installing Br1zz Security"
echo

# --- dependency check -------------------------------------------------------
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
    echo "Python 3.10 or newer is required." >&2
    exit 1
fi
ok "Python $(python3 -c 'import platform; print(platform.python_version())')"

MISSING=()
python3 -c 'import yara' 2>/dev/null && ok "yara-python present" || MISSING+=("python3-yara")
python3 -c 'import gi; gi.require_version("Gtk","4.0"); gi.require_version("Adw","1")' 2>/dev/null \
    && ok "GTK4 + libadwaita bindings present" \
    || MISSING+=("python3-gi" "gir1.2-gtk-4.0" "gir1.2-adw-1")

# --- CLI --------------------------------------------------------------------
mkdir -p "$BIN_DIR"
chmod +x "$ROOT/bin/br1zz-security"
ln -sf "$ROOT/bin/br1zz-security" "$BIN_DIR/br1zz-security"
ok "CLI installed at $BIN_DIR/br1zz-security"

# --- application icon -------------------------------------------------------
ICON_DIR="$HOME/.local/share/icons/hicolor"
if [ -d "$ROOT/assets/icons" ]; then
    for png in "$ROOT"/assets/icons/br1zz-security-*.png; do
        size="$(basename "$png" .png)"; size="${size##*-}"
        mkdir -p "$ICON_DIR/${size}x${size}/apps"
        cp "$png" "$ICON_DIR/${size}x${size}/apps/br1zz-security.png"
    done
    # The SVG is only installed when the system can actually rasterise one.
    # GTK prefers a scalable icon for any size it has no exact PNG for, so an
    # unrenderable SVG in the theme produces a broken-image placeholder rather
    # than falling back to the PNGs.
    # Actually rasterise the file rather than trusting the format table:
    # gdk-pixbuf lists "svg" among its formats on systems where the loader is
    # present but not registered, and loading then fails at runtime.
    if python3 -c "
import sys, gi
gi.require_version('GdkPixbuf', '2.0')
from gi.repository import GdkPixbuf, GLib
try:
    GdkPixbuf.Pixbuf.new_from_file_at_size('$ROOT/assets/br1zz-security.svg', 64, 64)
except GLib.Error:
    sys.exit(1)
" 2>/dev/null; then
        mkdir -p "$ICON_DIR/scalable/apps"
        cp "$ROOT/assets/br1zz-security.svg" "$ICON_DIR/scalable/apps/br1zz-security.svg"
    else
        rm -f "$ICON_DIR/scalable/apps/br1zz-security.svg"
        warn "No SVG loader found; installing PNG icons only"
    fi
    command -v gtk-update-icon-cache >/dev/null 2>&1 && \
        gtk-update-icon-cache -f -t "$ICON_DIR" 2>/dev/null || true
    ok "Application icon installed"
fi

# --- desktop entry ----------------------------------------------------------
mkdir -p "$APP_DIR"
sed "s|^Exec=br1zz-security gui$|Exec=$BIN_DIR/br1zz-security gui|" "$ROOT/br1zz-security.desktop" > "$APP_DIR/br1zz-security.desktop"
ok "Desktop entry installed"
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APP_DIR" 2>/dev/null || true

# --- systemd user units -----------------------------------------------------
mkdir -p "$UNIT_DIR"
sed "s|^ExecStart=.*|ExecStart=$BIN_DIR/br1zz-security scan --quick --no-progress --no-color|" \
    "$ROOT/systemd/br1zz-scan.service" > "$UNIT_DIR/br1zz-scan.service"
cp "$ROOT/systemd/br1zz-scan.timer" "$UNIT_DIR/br1zz-scan.timer"
sed "s|^ExecStart=.*|ExecStart=$BIN_DIR/br1zz-security --no-color watch|" \
    "$ROOT/systemd/br1zz-realtime.service" > "$UNIT_DIR/br1zz-realtime.service"
systemctl --user daemon-reload 2>/dev/null || true
ok "systemd user units installed (not enabled yet)"

# --- report -----------------------------------------------------------------
echo
if [ ${#MISSING[@]} -gt 0 ]; then
    warn "Optional packages missing: ${MISSING[*]}"
    echo "    Install them with:"
    echo "      sudo apt install ${MISSING[*]}"
    echo
    echo "    Br1zz runs without them - YARA rules and the GUI are simply"
    echo "    unavailable until they are installed."
    echo
fi

if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    warn "$BIN_DIR is not on your PATH. Add this to ~/.bashrc:"
    echo '      export PATH="$HOME/.local/bin:$PATH"'
    echo
fi

bold "Done."
cat <<EOF

  Get started:
    br1zz-security selftest                  verify the engines work
    br1zz-security scan ~/Downloads          scan a folder
    br1zz-security scan --quick              scan the usual risk areas
    br1zz-security gui                       open the desktop app

  Enable the daily background scan:
    systemctl --user enable --now br1zz-scan.timer

EOF
