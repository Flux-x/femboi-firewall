#!/usr/bin/env bash
# Femboi Firewall Linux build script
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SRC_DIR="linux/src"
XDP_DIR="linux/xdp"
INC_DIR="linux/include"
OUT_DIR="bin"
BIN_NAME="femboi-firewall"
XDP_BIN_NAME="femboi-firewall-xdp"
OBJ_DIR="bin/obj-linux"

WITH_DPI=0
WITH_CT=0
DEBUG=0
DO_INSTALL=0
DO_CLEAN=0
CHECK_ONLY=0
WERROR="${CXX_WERROR:-0}"

for arg in "$@"; do
    case "$arg" in
        --with-dpi) WITH_DPI=1 ;;
        --with-conntrack) WITH_CT=1 ;;
        --debug)    DEBUG=1 ;;
        --install)  DO_INSTALL=1 ;;
        --clean)    DO_CLEAN=1 ;;
        --check)    CHECK_ONLY=1 ;;
        --werror)   WERROR=1 ;;
        -h|--help)
            echo "Usage: ./derle.sh [--with-dpi] [--with-conntrack] [--debug] [--install] [--clean] [--check] [--werror]"
            exit 0
            ;;
        *) echo "[!] Unknown option: $arg" >&2; exit 2 ;;
    esac
done

c_reset=$'\033[0m'; c_ok=$'\033[92m'; c_info=$'\033[96m'; c_warn=$'\033[93m'; c_err=$'\033[91m'
say()  { printf '%s[*]%s %s\n' "$c_info" "$c_reset" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$c_ok"   "$c_reset" "$*"; }
warn() { printf '%s[!]%s %s\n' "$c_warn" "$c_reset" "$*"; }
err()  { printf '%s[-]%s %s\n' "$c_err"  "$c_reset" "$*" >&2; }
die()  { err "$*"; exit 1; }

# Remove build output artifacts
if [[ "$DO_CLEAN" -eq 1 ]]; then
    say "Cleaning build artifacts..."
    rm -rf "$OBJ_DIR" "$OUT_DIR/$BIN_NAME" "$OUT_DIR/$XDP_BIN_NAME"
    ok "Clean."
    [[ $# -eq 1 ]] && exit 0
fi

echo "=========================================="
echo " Femboi Firewall — Linux build"
echo "=========================================="

command -v g++ >/dev/null 2>&1 || die "g++ not found"
CXX="${CXX:-g++}"
say "compiler: $("$CXX" --version | head -1)"

DEFINES=()
LDLIBS=()
CFLAGS_NFQ=()

# Detect optional libnetfilter_queue for DPI
HAVE_NFQ=0
if [[ -f /usr/include/libnetfilter_queue/libnetfilter_queue.h ]]; then
    HAVE_NFQ=1
elif command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libnetfilter_queue; then
    HAVE_NFQ=1
fi

if [[ "$WITH_DPI" -eq 1 ]]; then
    if [[ "$HAVE_NFQ" -eq 1 ]]; then
        if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libnetfilter_queue; then
            LDLIBS+=($(pkg-config --libs libnetfilter_queue))
            CFLAGS_NFQ=($(pkg-config --cflags libnetfilter_queue))
        else
            LDLIBS+=(-lnetfilter_queue -lnfnetlink)
            CFLAGS_NFQ=()
        fi
        DEFINES+=(-DHAVE_NFQUEUE)
        ok "DPI: enabled"
    else
        warn "DPI missing libnetfilter_queue"
        WITH_DPI=0
    fi
fi

# Detect optional libnetfilter_conntrack for userspace handshake-gated auto-ban.
if [[ "$WITH_CT" -eq 1 ]]; then
    HAVE_CT=0
    if [[ -f /usr/include/libnetfilter_conntrack/libnetfilter_conntrack.h ]]; then
        HAVE_CT=1
    elif command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libnetfilter_conntrack; then
        HAVE_CT=1
    fi
    if [[ "$HAVE_CT" -eq 1 ]]; then
        if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libnetfilter_conntrack; then
            LDLIBS+=($(pkg-config --libs libnetfilter_conntrack))
            CFLAGS_NFQ+=($(pkg-config --cflags libnetfilter_conntrack))
        else
            LDLIBS+=(-lnetfilter_conntrack)
        fi
        DEFINES+=(-DHAVE_CONNTRACK)
        ok "conntrack handshake auto-ban: enabled"
    else
        warn "conntrack missing libnetfilter_conntrack"
    fi
fi

LDLIBS+=(-lpthread)

BASE_FLAGS=(-std=c++17 -Wall -Wextra -Wno-unused-parameter -pthread
            -I"$INC_DIR" -I"$SRC_DIR" -I"$XDP_DIR")
if [[ "$WERROR" == "1" ]]; then
    BASE_FLAGS+=(-Werror)
    say "warnings are errors (-Werror)"
fi
if [[ "$DEBUG" -eq 1 ]]; then
    BASE_FLAGS+=(-O0 -g3 -DDEBUG -fno-omit-frame-pointer)
else
    BASE_FLAGS+=(-O2 -DNDEBUG -fstack-protector-strong -D_FORTIFY_SOURCE=2)
fi
BASE_FLAGS+=(-fPIE -fstack-clash-protection)
LDFLAGS=(-pie -Wl,-z,relro,-z,now)

mkdir -p "$OUT_DIR" "$OBJ_DIR"

SOURCES=("$SRC_DIR/util.cpp" "$SRC_DIR/engine.cpp" "$SRC_DIR/nft.cpp"
         "$SRC_DIR/dpi.cpp" "$SRC_DIR/conntrack.cpp" "$SRC_DIR/main.cpp")

for f in "${SOURCES[@]}"; do
    [[ -f "$f" ]] || die "missing source: $f"
done

say "Compiling sources..."
OBJECTS=()
for f in "${SOURCES[@]}"; do
    obj="$OBJ_DIR/$(basename "${f%.cpp}").o"
    OBJECTS+=("$obj")
    printf '    %-28s' "$(basename "$f")"

    # `${VAR[@]+"${VAR[@]}"}` guards against `set -u` aborting when the array is
    # empty on bash < 4.4 (DPI disabled leaves CFLAGS_NFQ/DEFINES empty).
    if $CXX "${BASE_FLAGS[@]}" ${CFLAGS_NFQ[@]+"${CFLAGS_NFQ[@]}"} \
            ${DEFINES[@]+"${DEFINES[@]}"} \
            -c "$f" -o "$obj" 2>"$obj.log"; then
        printf '%sok%s\n' "$c_ok" "$c_reset"
        rm -f "$obj.log"
    else
        printf '%sFAIL%s\n' "$c_err" "$c_reset"
        echo
        err "compilation failed:"
        cat "$obj.log" | head -60
        exit 1
    fi
done

# Compile XDP CLI controller
XDP_SRC="$XDP_DIR/xdpctl.cpp"
XDP_OBJ="$OBJ_DIR/xdpctl.o"
[[ -f "$XDP_SRC" ]] || die "missing source: $XDP_SRC"
printf '    %-28s' "$(basename "$XDP_SRC")"
if $CXX "${BASE_FLAGS[@]}" ${DEFINES[@]+"${DEFINES[@]}"} \
        -c "$XDP_SRC" -o "$XDP_OBJ" 2>"$XDP_OBJ.log"; then
    printf '%sok%s\n' "$c_ok" "$c_reset"
    rm -f "$XDP_OBJ.log"
else
    printf '%sFAIL%s\n' "$c_err" "$c_reset"
    echo
    err "compilation failed:"
    cat "$XDP_OBJ.log" | head -60
    exit 1
fi

if [[ "$CHECK_ONLY" -eq 1 ]]; then
    ok "Syntax check passed."
    exit 0
fi

# Link main firewall binary
TARGET="$OUT_DIR/$BIN_NAME"
say "Linking $TARGET..."
if ! $CXX "${OBJECTS[@]}" -o "$TARGET" "${LDFLAGS[@]}" "${LDLIBS[@]}"; then
    die "link failed"
fi
chmod +x "$TARGET"

# Link XDP controller binary
XDP_TARGET="$OUT_DIR/$XDP_BIN_NAME"
say "Linking $XDP_TARGET..."
if ! $CXX "$OBJ_DIR/util.o" "$XDP_OBJ" -o "$XDP_TARGET" "${LDFLAGS[@]}" "${LDLIBS[@]}"; then
    die "link failed ($XDP_BIN_NAME)"
fi
chmod +x "$XDP_TARGET"

ok "Built $TARGET"
ok "Built $XDP_TARGET"

# Copy GeoIP database if present
if [[ -f geoip.dat && ! -f "$OUT_DIR/geoip.dat" ]]; then
    cp -f geoip.dat "$OUT_DIR/geoip.dat"
    ok "Copied geoip.dat"
fi

# Install binaries to system
if [[ "$DO_INSTALL" -eq 1 ]]; then
    [[ $EUID -eq 0 ]] || die "--install needs root"
    say "Installing..."
    install -d /etc/femboi /usr/share/femboi /var/lib/femboi
    install -m 0755 "$TARGET" /usr/local/bin/femboi-firewall
    install -m 0755 "$XDP_TARGET" /usr/local/bin/femboi-firewall-xdp
    [[ -f geoip.dat ]] && install -m 0644 geoip.dat /usr/share/femboi/geoip.dat
    if [[ ! -f /etc/femboi/firewall.conf ]]; then
        install -m 0644 firewall.conf.example /etc/femboi/firewall.conf
        ok "Installed /etc/femboi/firewall.conf"
    fi
    chmod 0700 /var/lib/femboi

    # Build and install the eBPF datapath object (CO-RE) so the systemd unit's
    # ExecStartPre can attach it. Best-effort: a missing clang/bpftool must not
    # fail an otherwise successful daemon install.
    if command -v clang >/dev/null 2>&1 && command -v bpftool >/dev/null 2>&1; then
        if make -C linux/xdp bpf >/dev/null 2>&1; then
            install -d /usr/lib/femboi
            if [[ -f linux/bin/femboi_xdp.o ]]; then
                install -m 0644 linux/bin/femboi_xdp.o /usr/lib/femboi/femboi_xdp.o
                ok "Installed /usr/lib/femboi/femboi_xdp.o"
            fi
        else
            warn "XDP object build failed (attach will be skipped)"
        fi
    else
        warn "clang/bpftool missing: XDP object not built"
    fi

    # Install the systemd unit (README documents `systemctl enable --now`).
    if [[ -f deploy/femboi-firewall.service ]]; then
        install -m 0644 deploy/femboi-firewall.service /lib/systemd/system/femboi-firewall.service
        ok "Installed /lib/systemd/system/femboi-firewall.service"
        command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1 || true
    else
        warn "deploy/femboi-firewall.service missing; systemd unit not installed"
    fi

    ok "Installed. Enable: systemctl enable --now femboi-firewall"
fi

echo "=========================================="
ok "Build finished."
echo "=========================================="
