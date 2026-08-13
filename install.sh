#!/bin/sh
# Install SafePaste for the current user only, no root required.
#
# The .deb (packaging/build-deb.sh) is the better route if you have sudo — it
# installs system-wide and enables the unit for every user. This exists for the
# case where you do not, or where you want to run straight from a checkout.
set -eu

REPO=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PREFIX="${PREFIX:-$HOME/.local}"
LIBDIR="$PREFIX/lib/safepaste"
BINDIR="$PREFIX/bin"
UNITDIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
DESKTOPDIR="$PREFIX/share/applications"

# --- dependencies ---------------------------------------------------------
# These cannot be pip-installed usefully: python3-gi must match the distro's
# GTK4/libadwaita, so a venv-local copy would not see them.
missing=""
for probe in "gi:python3-gi" "regex:python3-regex" "Xlib:python3-xlib"; do
    module=${probe%%:*}
    package=${probe#*:}
    python3 -c "import $module" >/dev/null 2>&1 || missing="$missing $package"
done
if ! command -v wl-copy >/dev/null 2>&1; then
    missing="$missing wl-clipboard"
fi
if [ -n "$missing" ]; then
    echo "Missing dependencies. Install them first:" >&2
    echo >&2
    echo "    sudo apt install$missing" >&2
    echo >&2
    exit 1
fi

python3 - <<'EOF' || { echo "GTK4 and libadwaita typelibs are required (gir1.2-gtk-4.0, gir1.2-adw-1)" >&2; exit 1; }
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
EOF

# --- install --------------------------------------------------------------
echo "installing to $LIBDIR"
mkdir -p "$LIBDIR" "$BINDIR" "$UNITDIR" "$DESKTOPDIR"
rm -rf "$LIBDIR/safepaste"
cp -r "$REPO/safepaste" "$LIBDIR/"
find "$LIBDIR/safepaste" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "$LIBDIR/safepaste" -name '*.py[co]' -delete

for required in gitleaks.toml safepaste-extra.toml; do
    if [ ! -f "$LIBDIR/safepaste/detector/data/$required" ]; then
        echo "missing rule data: $required — run scripts/fetch-rules.py first" >&2
        exit 1
    fi
done

# PYTHONPATH is set inside the shim rather than exported into your shell, so this
# install cannot affect anything else you run.
write_shim() {
    cat > "$BINDIR/$1" <<EOF
#!/bin/sh
exec python3 -c 'import sys; sys.path.insert(0, "$LIBDIR"); from $2 import main; sys.exit(main())' "\$@"
EOF
    chmod 0755 "$BINDIR/$1"
}
write_shim safepaste        safepaste.cli
write_shim safepaste-daemon safepaste.daemon
write_shim safepaste-gui    safepaste.app

# The unit ships with ExecStart=/usr/bin/safepaste-gui for the packaged layout;
# point it at this one instead.
sed "s|^ExecStart=.*|ExecStart=$BINDIR/safepaste-gui|" \
    "$REPO/packaging/systemd/safepaste.service" > "$UNITDIR/safepaste.service"
sed "s|^Exec=.*|Exec=$BINDIR/safepaste-gui|" \
    "$REPO/packaging/safepaste.desktop" > "$DESKTOPDIR/safepaste.desktop"

systemctl --user daemon-reload
systemctl --user enable safepaste.service >/dev/null

cat <<EOF

SafePaste installed for $(id -un).

Start it now:            systemctl --user start safepaste.service
Check it is running:     systemctl --user status safepaste.service
Bind Ctrl+Alt+V:         $BINDIR/safepaste --help  # then: python3 -m safepaste.hotkey install
Uninstall:               systemctl --user disable --now safepaste.service
                         rm -rf "$LIBDIR" "$BINDIR"/safepaste* "$UNITDIR/safepaste.service"

EOF

case ":$PATH:" in
    *":$BINDIR:"*) ;;
    *) echo "Note: $BINDIR is not on your PATH." ;;
esac
