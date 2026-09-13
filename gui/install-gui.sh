#!/bin/bash
# Install the firewall desktop application (menu entry + icon + panel).
#
# Separate from the daemon install on purpose: the daemon is a system service
# that must exist on a headless box, while the panel is only meaningful where
# there is a session to click in. Installing them together would drag a GUI
# toolchain onto machines that will never open a window.
set -e

SRC="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

export DEBIAN_FRONTEND=noninteractive

echo "=== tkinter (the panel is Tk, and Debian keeps it in a separate package) ==="
if ! python3 -c "import tkinter" >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y python3-tk
else
    echo "  already present"
fi

echo
echo "=== installing files ==="
install -d /usr/local/bin
install -d /usr/share/icons/hicolor/scalable/apps
install -d /usr/share/applications

install -m 0755 "$SRC/fw-gui"             /usr/local/bin/fw-gui
install -m 0644 "$SRC/fw.svg"             /usr/share/icons/hicolor/scalable/apps/fw.svg
install -m 0644 "$SRC/fw.desktop"         /usr/share/applications/fw.desktop

echo "  /usr/local/bin/fw-gui"
echo "  /usr/share/applications/fw.desktop"
echo "  /usr/share/icons/hicolor/scalable/apps/fw.svg"

echo
echo "=== refreshing the menu and icon caches ==="
update-desktop-database /usr/share/applications 2>/dev/null || echo "  (update-desktop-database not available)"
gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || echo "  (gtk-update-icon-cache not available)"

echo
echo "=== smoke test ==="
/usr/local/bin/fw-gui --check || echo "  !! check reported a problem"

echo
echo "=== menu entry validity ==="
if command -v desktop-file-validate >/dev/null 2>&1; then
    desktop-file-validate /usr/share/applications/fw.desktop && echo "  valid"
else
    grep -E '^(Type|Name|Exec|Icon|Categories)=' /usr/share/applications/femboi-firewall.desktop | sed 's/^/  /'
fi

echo
echo "[+] done. It appears under Applications -> System, or search for 'Femboi'."
