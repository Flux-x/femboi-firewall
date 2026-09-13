#!/usr/bin/env bash
# Cross-compile the Fluxx Firewall desktop panel from Windows.
#
# Why this is more involved than the firewall build: the daemon is static musl
# with zero dependencies, so `zig c++ -static` is the whole story. A GUI is the
# opposite — it links GLFW and the X11 client stack, which on a desktop are shared
# libraries by design. So:
#
#   * GLFW is vendored and compiled into the binary. The target has libX11 and
#     libGL but no libglfw.so.3, and shipping a .so next to a binary is how you
#     end up with two copies of a library on one host.
#   * The X11/GL HEADERS come from a fetched sysroot (fetch-sysroot.py), so
#     nothing has to be installed on the target to build for it.
#   * The binary dynamically links libX11/libGL, which every desktop install
#     already has. That is the correct dependency to have: those are exactly the
#     libraries the GUI cannot function without anyway.
#
# Usage:
#   ./gui-derle.sh              build bin/fluxxfw-gui
#   ./gui-derle.sh --clean
#   ./gui-derle.sh --check      compile only, do not link
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

# zig lives with the firewall build; reuse it rather than downloading a second copy.
ZIG="${ZIG:-$HERE/../../tools/zig/zig.exe}"
[[ -x "$ZIG" ]] || ZIG="$(command -v zig 2>/dev/null || true)"
SYSROOT="${SYSROOT:-$HERE/.sysroot}"
TARGET="${TARGET:-x86_64-linux-gnu}"
OUT_DIR="bin"
OBJ_DIR="bin/obj"
BIN="$OUT_DIR/fw-gui"

DO_CLEAN=0
CHECK_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --clean) DO_CLEAN=1 ;;
        --check) CHECK_ONLY=1 ;;
        -h|--help) sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "[!] unknown option: $arg" >&2; exit 2 ;;
    esac
done

if [[ "$DO_CLEAN" -eq 1 ]]; then
    rm -rf "$OBJ_DIR" "$BIN"
    echo "[+] cleaned"
    [[ $# -eq 1 ]] && exit 0
fi

die() { echo "[HATA] $*" >&2; exit 1; }

echo "=========================================="
echo " Femboi Firewall panel — cross build"
echo " target: $TARGET   host: Windows"
echo "=========================================="

[[ -n "$ZIG" && -x "$ZIG" ]] || die "zig not found. Build the firewall once (derle.bat) to fetch it, or set ZIG=..."
echo "[+] zig: $("$ZIG" version)"

[[ -d glfw/src ]] || die "glfw/ sources missing — expected glfw/src/*.c"
[[ -d imgui ]] || die "imgui/ sources missing"
[[ -f fw_gui.cpp ]] || die "fw_gui.cpp missing"

# ---- sysroot ---------------------------------------------------------------
if [[ ! -d "$SYSROOT/usr/include/X11" ]]; then
    echo
    echo "[*] X11 headers not present — fetching the sysroot"
    echo "    (target-side headers only; nothing is installed on the server)"
    python "$HERE/fetch-sysroot.py" || die "could not fetch the sysroot"
    SYSROOT_MOVED=1
fi
[[ -d "$SYSROOT/usr/include/X11" ]] || die "no X11 headers at $SYSROOT/usr/include"
echo "[+] sysroot: $SYSROOT"

SYSINC="$SYSROOT/usr/include"
SYSLIB="$SYSROOT/usr/lib/x86_64-linux-gnu"
[[ -d "$SYSLIB" ]] || die "no libraries at $SYSLIB"

# ---- flags -----------------------------------------------------------------
CFLAGS_COMMON=(-target "$TARGET" -O2 -w -isystem "$SYSINC")
CFLAGS_C=(-D_GLFW_X11 -Iglfw/include -Iglfw/src)
CFLAGS_CXX=(-std=c++17 -DNDEBUG -Iimgui -Iglfw/include -I. -I../include)
LDFLAGS=(-target "$TARGET")

mkdir -p "$OUT_DIR" "$OBJ_DIR"

# ---- 1. GLFW (C) -----------------------------------------------------------
#
# The source list is explicit rather than `glfw/src/*.c`: the glob pulls in
# cocoa_time.c, the win32_* files and the Wayland backend, and the first of those
# to be compiled aborts the build with a missing macOS header. These are exactly
# the translation units GLFW's own CMakeLists selects for the X11 platform.
echo
echo "[*] GLFW 3.4 (X11 backend, compiled in)"
GLFW_SRC=(
    glfw/src/context.c glfw/src/init.c glfw/src/input.c glfw/src/monitor.c
    glfw/src/platform.c glfw/src/vulkan.c glfw/src/window.c
    glfw/src/egl_context.c glfw/src/glx_context.c glfw/src/osmesa_context.c
    glfw/src/null_init.c glfw/src/null_monitor.c glfw/src/null_window.c
    glfw/src/null_joystick.c
    glfw/src/x11_init.c glfw/src/x11_monitor.c glfw/src/x11_window.c
    glfw/src/xkb_unicode.c glfw/src/linux_joystick.c
    glfw/src/posix_module.c glfw/src/posix_thread.c glfw/src/posix_time.c
    glfw/src/posix_poll.c
)
GLFW_OBJS=()
for f in "${GLFW_SRC[@]}"; do
    obj="$OBJ_DIR/glfw_$(basename "${f%.c}").o"
    GLFW_OBJS+=("$obj")
    if [[ ! -f "$obj" || "$f" -nt "$obj" ]]; then
        printf '    %-30s' "$(basename "$f")"
        if "$ZIG" cc "${CFLAGS_COMMON[@]}" "${CFLAGS_C[@]}" -c "$f" -o "$obj" 2>"$obj.log"; then
            printf 'ok\n'
            rm -f "$obj.log"
        else
            printf 'FAIL\n'
            head -20 "$obj.log"
            die "glfw compile failed: $f"
        fi
    fi
done

# ---- 2. ImGui + the panel (C++) -------------------------------------------
echo
echo "[*] ImGui + panel"
CPP_SRC=(
    fw_gui.cpp
    imgui/imgui.cpp
    imgui/imgui_draw.cpp
    imgui/imgui_tables.cpp
    imgui/imgui_widgets.cpp
    imgui/imgui_impl_glfw.cpp
    imgui/imgui_impl_opengl3.cpp
)
CPP_OBJS=()
for f in "${CPP_SRC[@]}"; do
    obj="$OBJ_DIR/$(basename "${f%.cpp}").o"
    CPP_OBJS+=("$obj")
    printf '    %-30s' "$(basename "$f")"
    if "$ZIG" c++ "${CFLAGS_COMMON[@]}" "${CFLAGS_CXX[@]}" -c "$f" -o "$obj" 2>"$obj.log"; then
        printf 'ok\n'
        rm -f "$obj.log"
    else
        printf 'FAIL\n'
        head -30 "$obj.log"
        die "compile failed: $f"
    fi
done

if [[ "$CHECK_ONLY" -eq 1 ]]; then
    echo
    echo "[+] compile-only pass finished, not linked"
    exit 0
fi

# ---- 3. link ---------------------------------------------------------------
echo
echo "[*] linking"

# Pass the versioned .so files by path: ld records their SONAME, so the binary
# asks for libX11.so.6 at runtime, which is what the target actually has.
SYSLIBS=()
for name in libX11 libXcursor libXrandr libXinerama libXi libXext libGL; do
    found=""
    for cand in "$SYSLIB/$name.so" "$SYSLIB/$name".so.*; do
        [[ -e "$cand" ]] && { found="$cand"; break; }
    done
    [[ -n "$found" ]] && SYSLIBS+=("$found")
done
echo "    libraries: $(for l in "${SYSLIBS[@]}"; do basename "$l"; done | tr '\n' ' ')"

if ! "$ZIG" c++ "${LDFLAGS[@]}" -o "$BIN" "${GLFW_OBJS[@]}" "${CPP_OBJS[@]}" \
        "${SYSLIBS[@]}" -lpthread -ldl 2>"$OBJ_DIR/link.log"; then
    echo "[HATA] link failed:"
    head -40 "$OBJ_DIR/link.log"
    exit 1
fi
rm -f "$OBJ_DIR/link.log"

# ---- 4. verify it is a Linux ELF -------------------------------------------
magic=$(head -c 4 "$BIN" | od -An -tx1 | tr -d ' \n')
if [[ "$magic" != "7f454c46" ]]; then
    die "output is not an ELF (magic $magic)"
fi

echo
echo "=========================================="
echo " [BASARILI] $BIN"
echo "=========================================="
printf '  boyut  : %s byte\n' "$(stat -c%s "$BIN")"
printf '  sha256 : %s\n' "$(sha256sum "$BIN" | cut -d' ' -f1)"
echo
echo "  Sunucuya kopyala:  scp $BIN root@VDS:/usr/local/bin/fw-gui
  Calistir (RDP oturumunda):  fw-gui"
echo
echo "  Runtime bagimliligi: libX11, libGL, libXcursor, libXrandr, libXinerama, libXi"
echo "  Bunlar XFCE kurulu her masaustunde zaten var; GLFW gomulu, ayrica kurulmaz."
