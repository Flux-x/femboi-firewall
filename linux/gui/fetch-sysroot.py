#!/usr/bin/env python3
"""Fetch the X11/GL development headers into a cross-build sysroot.

Why this exists: the firewall cross-compiles from Windows trivially because it is
static musl with zero dependencies. A GUI is the opposite — it links GLFW and the
X11 client stack, which on a desktop system are shared libraries by design. To
build it anywhere other than the target, the target's headers and linker stubs
have to be brought along.

The package index is read rather than guessing pool URLs, because Debian pool
filenames carry version numbers that change.

Every URL is checked before it is fetched. The paths come from a remote index,
which makes this a data-driven fetch: a compromised or mistyped index entry could
otherwise point the download at a private address. So the scheme and host are
allowlisted, the index-supplied filename must be a plain relative path, and the
resolved address must be public.
"""

import io
import ipaddress
import lzma
import os
import socket
import sys
import urllib.parse
import urllib.request

MIRROR_HOST = "deb.debian.org"
MIRROR = f"https://{MIRROR_HOST}/debian"
SUITE = "trixie"
COMPONENT = "main"
ARCH = "amd64"

ALLOWED_SCHEMES = {"https"}
ALLOWED_HOSTS = {"deb.debian.org", "security.debian.org"}

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("SYSROOT", os.path.join(HERE, ".sysroot"))

WANT = [
    "libx11-dev", "libxau-dev", "libxdmcp-dev", "libxcb1-dev", "x11proto-dev",
    "libxext-dev", "libxrender-dev", "xtrans-dev",
    # XInput2.h includes Xfixes.h, so GLFW's X11 backend will not compile without it
    "libxfixes-dev", "libxfixes3",
    "libxrandr-dev", "libxinerama-dev", "libxcursor-dev", "libxi-dev",
    "libgl-dev", "libglx-dev", "libgl1", "libglvnd-dev",
    "libx11-6", "libxrandr2", "libxinerama1", "libxcursor1", "libxi6",
    "libxext6", "libxrender1",
]


def _check_public(url):
    """Reject anything that is not https to an allowlisted, publicly-routed host."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"refusing scheme {parts.scheme!r}")
    if parts.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"refusing host {parts.hostname!r}")
    for info in socket.getaddrinfo(parts.hostname, 443, proto=socket.IPPROTO_TCP):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or \
           ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise ValueError(f"refusing resolved address {ip}")
    return url


def fetch(url, timeout=120):
    _check_public(url)
    req = urllib.request.Request(url, headers={"User-Agent": "fluxx-crossbuild"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - validated above
        return r.read()


def safe_relpath(name):
    """An index-supplied filename must be a plain relative path.

    The other half of the check: even with an allowlisted host, a Filename of
    "../../../etc/passwd" would escape the pool directory.
    """
    if not name or name.startswith("/") or "://" in name:
        return None
    parts = name.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return None
    return name


def package_index():
    url = f"{MIRROR}/dists/{SUITE}/{COMPONENT}/binary-{ARCH}/Packages.xz"
    print(f"[*] reading index {url}")
    text = lzma.decompress(fetch(url, timeout=300)).decode("utf-8", "replace")

    index = {}
    cur = None
    for line in text.splitlines():
        if line.startswith("Package: "):
            cur = line[9:].strip()
        elif line.startswith("Filename: ") and cur:
            rel = safe_relpath(line[10:].strip())
            if rel:
                index[cur] = rel
            cur = None
    print(f"[+] index: {len(index)} packages")
    return index


def ar_members(blob):
    """Yield the data.tar member of a .deb, which is an ar archive."""
    if blob[:8] != b"!<arch>\n":
        return
    off = 8
    while off + 60 <= len(blob):
        header = blob[off:off + 60]
        name = header[0:16].decode("ascii", "replace").strip()
        try:
            size = int(header[48:58].decode("ascii").strip())
        except ValueError:
            return
        start = off + 60
        data = blob[start:start + size]
        off = start + size + (size & 1)
        if name.startswith("data.tar"):
            yield name, data
            return


def unpack(data, dest):
    if data[:6] == b"\xfd7zXZ\x00":
        data = lzma.decompress(data)
    import tarfile
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        for m in tf.getmembers():
            # Never let an archive member escape the sysroot.
            cleaned = m.name.lstrip("./").lstrip("/")
            if not cleaned or ".." in cleaned.split("/"):
                continue
            m.name = cleaned
            tf.extract(m, dest)


def main():
    os.makedirs(OUT, exist_ok=True)
    index = package_index()

    got, missed = 0, []
    for pkg in WANT:
        rel = index.get(pkg)
        if not rel:
            missed.append(pkg)
            continue
        try:
            for _name, data in ar_members(fetch(f"{MIRROR}/{rel}")):
                unpack(data, OUT)
            print(f"  [+] {pkg}")
            got += 1
        except Exception as exc:  # noqa: BLE001
            print(f"  ! {pkg}: {exc}")
            missed.append(pkg)

    print()
    print(f"[+] unpacked {got}/{len(WANT)} packages into {OUT}")
    if missed:
        print(f"[!] not fetched: {' '.join(missed)}")

    inc = os.path.join(OUT, "usr", "include")
    lib = os.path.join(OUT, "usr", "lib", "x86_64-linux-gnu")
    print()
    print("sysroot layout:")
    for label, p in (("headers", os.path.join(inc, "X11")), ("libs", lib)):
        if os.path.isdir(p):
            print(f"  {label}: {p} ({len(os.listdir(p))} entries)")
        else:
            print(f"  {label}: MISSING ({p})")

    made = 0
    if os.path.isdir(lib):
        for entry in os.listdir(lib):
            if ".so." in entry:
                target = os.path.join(lib, entry.split(".so.")[0] + ".so")
                if not os.path.exists(target):
                    try:
                        os.symlink(entry, target)
                        made += 1
                    except OSError:
                        pass
    print(f"  linker symlinks created: {made}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
