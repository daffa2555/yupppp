#!/bin/sh
set -eu

REPO="${YUPP_REPO:-daffa2555/yupppp}"
INSTALL_DIR="${YUPP_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${YUPP_VERSION:-}"

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'yupp installer error: required command not found: %s\n' "$1" >&2
        exit 1
    fi
}

need_cmd curl
need_cmd tar
need_cmd uname
need_cmd mktemp
need_cmd awk
need_cmd sed

OS="$(uname -s)"
ARCH="$(uname -m)"

case "${OS}:${ARCH}" in
    Linux:x86_64 | Linux:amd64)
        TARGET="x86_64-unknown-linux-gnu"
        ;;
    Darwin:arm64 | Darwin:aarch64)
        TARGET="aarch64-apple-darwin"
        ;;
    Darwin:x86_64 | Darwin:amd64)
        TARGET="x86_64-apple-darwin"
        ;;
    *)
        printf 'yupp installer error: unsupported platform %s/%s.\n' "$OS" "$ARCH" >&2
        printf 'Install from source instead: cargo install --git https://github.com/%s\n' "$REPO" >&2
        exit 1
        ;;
esac

if [ -z "$VERSION" ]; then
    API_URL="https://api.github.com/repos/${REPO}/releases/latest"
    VERSION="$(curl -fsSL "$API_URL" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
    if [ -z "$VERSION" ]; then
        printf 'yupp installer error: failed to determine latest release from %s\n' "$API_URL" >&2
        printf 'You can specify a version explicitly via YUPP_VERSION=v0.1.0 or build from source:\n' >&2
        printf '  cargo install --git https://github.com/%s\n' "$REPO" >&2
        exit 1
    fi
fi

case "$VERSION" in
    v*) ;;
    *) VERSION="v${VERSION}" ;;
esac

ARCHIVE="yupp-${VERSION}-${TARGET}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
ARCHIVE_URL="${BASE_URL}/${ARCHIVE}"
CHECKSUMS_URL="${BASE_URL}/SHA256SUMS.txt"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT INT TERM

printf 'Downloading yupp %s (%s)...\n' "$VERSION" "$TARGET"
curl -fsSL "$ARCHIVE_URL" -o "$WORK_DIR/$ARCHIVE"
curl -fsSL "$CHECKSUMS_URL" -o "$WORK_DIR/SHA256SUMS.txt"

EXPECTED_SHA="$(awk -v f="$ARCHIVE" '{ sub(/\r$/, "") } $2 == f || $2 == "*" f { print $1; exit }' "$WORK_DIR/SHA256SUMS.txt")"
if [ -z "$EXPECTED_SHA" ]; then
    printf 'yupp installer error: checksum entry for %s not found in SHA256SUMS.txt\n' "$ARCHIVE" >&2
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_SHA="$(sha256sum "$WORK_DIR/$ARCHIVE" | awk '{ print $1 }')"
elif command -v shasum >/dev/null 2>&1; then
    ACTUAL_SHA="$(shasum -a 256 "$WORK_DIR/$ARCHIVE" | awk '{ print $1 }')"
else
    printf 'yupp installer error: neither sha256sum nor shasum is available to verify checksum\n' >&2
    exit 1
fi

if [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
    printf 'yupp installer error: SHA-256 checksum mismatch for %s!\n' "$ARCHIVE" >&2
    printf '  expected: %s\n' "$EXPECTED_SHA" >&2
    printf '  actual:   %s\n' "$ACTUAL_SHA" >&2
    exit 1
fi
printf 'Verified SHA-256 checksum (%s)\n' "$ACTUAL_SHA"

tar -xzf "$WORK_DIR/$ARCHIVE" -C "$WORK_DIR"
if [ ! -f "$WORK_DIR/yupp" ]; then
    printf 'yupp installer error: archive did not contain yupp binary\n' >&2
    exit 1
fi

mkdir -p "$INSTALL_DIR"
TMP_BIN="$INSTALL_DIR/.yupp.tmp.$$"
cp "$WORK_DIR/yupp" "$TMP_BIN"
chmod +x "$TMP_BIN"
mv -f "$TMP_BIN" "$INSTALL_DIR/yupp"

printf 'Installed yupp to %s/yupp\n' "$INSTALL_DIR"

case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
        printf '\nNote: %s is not in your PATH. Add it with:\n' "$INSTALL_DIR"
        printf '  export PATH="%s:$PATH"\n' "$INSTALL_DIR"
        ;;
esac

"$INSTALL_DIR/yupp" --version || true
