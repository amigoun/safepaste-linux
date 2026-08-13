#!/bin/sh
# Build safepaste_<version>_all.deb.
#
# Uses plain dpkg-deb rather than debhelper/dpkg-buildpackage: this is an
# Architecture: all pure-Python package with no compiled extension and no build
# step, so debhelper would add a dependency without doing anything for us.
# Needs no root — --root-owner-group gets the ownership right without fakeroot.
set -eu

REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$REPO"

# Single source of truth for the version: the package itself. Hardcoding it in
# control as well would guarantee the two drift apart.
VERSION=$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' safepaste/__init__.py)
if [ -z "$VERSION" ]; then
    echo "could not read __version__ from safepaste/__init__.py" >&2
    exit 1
fi

PKGDIR=$(mktemp -d)
trap 'rm -rf "$PKGDIR"' EXIT
OUT="$REPO/dist"
SITE="$PKGDIR/usr/lib/python3/dist-packages"

echo "building safepaste $VERSION"

mkdir -p "$SITE" "$PKGDIR/usr/bin" "$PKGDIR/DEBIAN" \
         "$PKGDIR/usr/lib/systemd/user" "$PKGDIR/usr/share/applications" \
         "$PKGDIR/usr/share/doc/safepaste" "$OUT"

# --- the Python package ---------------------------------------------------
# Copy the tree, then prune anything that must not ship. Listing what to exclude
# is safer than listing what to include: a new module added later ships
# automatically instead of being silently left out.
cp -r safepaste "$SITE/"
find "$SITE/safepaste" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "$SITE/safepaste" -name '*.py[co]' -delete

# The vendored rule set is data, not code, and the detector is useless without
# it. Fail loudly rather than shipping a package that finds nothing.
for required in gitleaks.toml safepaste-extra.toml gitleaks.provenance.json; do
    if [ ! -f "$SITE/safepaste/detector/data/$required" ]; then
        echo "missing rule data file: $required (run scripts/fetch-rules.py)" >&2
        exit 1
    fi
done

# --- entry points ---------------------------------------------------------
# Thin shims rather than console_scripts: no setuptools at runtime, and each is
# obvious enough to debug by reading.
write_shim() {
    cat > "$PKGDIR/usr/bin/$1" <<EOF
#!/usr/bin/python3
import sys

from $2 import main

sys.exit(main())
EOF
    chmod 0755 "$PKGDIR/usr/bin/$1"
}
write_shim safepaste        safepaste.cli
write_shim safepaste-daemon safepaste.service
write_shim safepaste-gui    safepaste.app

# --- packaging metadata ---------------------------------------------------
sed "s/@VERSION@/$VERSION/" packaging/deb/DEBIAN/control > "$PKGDIR/DEBIAN/control"
for script in postinst prerm postrm; do
    if [ -f "packaging/deb/DEBIAN/$script" ]; then
        cp "packaging/deb/DEBIAN/$script" "$PKGDIR/DEBIAN/$script"
        chmod 0755 "$PKGDIR/DEBIAN/$script"
    fi
done

cp packaging/systemd/safepaste.service "$PKGDIR/usr/lib/systemd/user/"
cp packaging/safepaste.desktop "$PKGDIR/usr/share/applications/"
if [ -f README.md ]; then
    cp README.md "$PKGDIR/usr/share/doc/safepaste/"
fi

# Normalise permissions: files copied from a working tree carry whatever the
# developer's umask happened to be (0664 here), which lintian flags. Sweep
# everything to 0644 first, then re-mark the things that must be executable —
# safer than enumerating the directories that need fixing and missing one.
find "$PKGDIR" -type d -exec chmod 0755 {} +
find "$PKGDIR" -type f -exec chmod 0644 {} +
chmod 0755 "$PKGDIR/usr/bin/"*
for script in postinst prerm postrm; do
    if [ -f "$PKGDIR/DEBIAN/$script" ]; then
        chmod 0755 "$PKGDIR/DEBIAN/$script"
    fi
done

DEB="$OUT/safepaste_${VERSION}_all.deb"
dpkg-deb --build --root-owner-group "$PKGDIR" "$DEB"

echo
echo "=== dpkg-deb --info ==="
dpkg-deb --info "$DEB"
echo
echo "=== dpkg-deb --contents ==="
dpkg-deb --contents "$DEB"
echo
if command -v lintian >/dev/null 2>&1; then
    echo "=== lintian ==="
    lintian "$DEB" || true
else
    echo "(lintian not installed; skipping)"
fi
echo
echo "built $DEB"
ls -lh "$DEB"
