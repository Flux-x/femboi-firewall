#!/usr/bin/env bash
# Femboi Firewall — GeoIP dataset updater.
#
# Downloads the compact `geoip.dat`, verifies its integrity, and atomically
# installs it. Integrity is MANDATORY: the `.sha256` sidecar must be present and
# must match, otherwise nothing is installed. If GEOIP_PUBKEY is set, a detached
# GPG signature (`geoip.dat.asc`) is verified as well, giving supply-chain
# protection against a tampered mirror.
#
# Environment:
#   GEOIP_URL      Base URL that serves geoip.dat and geoip.dat.sha256
#                  (e.g. https://example.org/femboi). Required.
#   GEOIP_SHA256   Optional expected digest; when set, overrides the sidecar and
#                  no .sha256 download is performed.
#   GEOIP_PUBKEY   Optional path to an armored GPG public key. Enables .asc
#                  signature verification.
#   GEOIP_DEST     Install path (default /usr/share/femboi/geoip.dat).
#   RELOAD         Set to 0 to skip `systemctl reload femboi-firewall`.
#
# Usage: sudo GEOIP_URL=https://.../femboi ./tools/geoip/update.sh
set -euo pipefail

GEOIP_DEST="${GEOIP_DEST:-/usr/share/femboi/geoip.dat}"
RELOAD="${RELOAD:-1}"

log() { printf '[*] %s\n' "$*"; }
die() { printf '[-] %s\n' "$*" >&2; exit 1; }

[[ -n "${GEOIP_URL:-}" ]] || die "GEOIP_URL is required"

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

dl() {
    # fetch <url> <dest>
    curl -fsSL --retry 3 --proto '=https' --tlsv1.2 "$1" -o "$2" \
        || die "download failed: $1"
}

log "downloading dataset"
dl "${GEOIP_URL%/}/geoip.dat" "$tmpdir/geoip.dat"

if [[ -n "${GEOIP_SHA256:-}" ]]; then
    expected="$GEOIP_SHA256"
else
    log "downloading checksum"
    dl "${GEOIP_URL%/}/geoip.dat.sha256" "$tmpdir/geoip.dat.sha256"
    # Sidecar may be "<hex>  geoip.dat" or just "<hex>".
    expected="$(awk '{print $1}' "$tmpdir/geoip.dat.sha256" | head -1)"
fi

[[ -n "$expected" ]] || die "empty checksum; refusing to install"
actual="$(sha256sum "$tmpdir/geoip.dat" | awk '{print $1}')"
[[ "$actual" == "$expected" ]] || die "checksum mismatch: expected $expected, got $actual"
log "checksum ok: $actual"

if [[ -n "${GEOIP_PUBKEY:-}" ]]; then
    command -v gpg >/dev/null 2>&1 || die "GEOIP_PUBKEY set but gpg not installed"
    log "verifying detached signature"
    dl "${GEOIP_URL%/}/geoip.dat.asc" "$tmpdir/geoip.dat.asc"
    gpg --batch --no-default-keyring --keyring "$tmpdir/ring.gpg" \
        --import "$GEOIP_PUBKEY" >/dev/null 2>&1 || die "cannot import GEOIP_PUBKEY"
    gpg --batch --no-default-keyring --keyring "$tmpdir/ring.gpg" \
        --verify "$tmpdir/geoip.dat.asc" "$tmpdir/geoip.dat" \
        || die "signature verification failed"
    log "signature ok"
fi

install_dir="$(dirname "$GEOIP_DEST")"
install -d -m 0755 "$install_dir"
# Atomic replace: a reader (the daemon) never sees a half-written dataset.
install -m 0644 "$tmpdir/geoip.dat" "${GEOIP_DEST}.new"
mv -f "${GEOIP_DEST}.new" "$GEOIP_DEST"
# The daemon checks this sidecar on load when present.
printf '%s  %s\n' "$actual" "$(basename "$GEOIP_DEST")" > "${GEOIP_DEST}.sha256"
log "installed $GEOIP_DEST"

if [[ "$RELOAD" == "1" ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl reload femboi-firewall 2>/dev/null && log "reloaded daemon" || true
fi
