#!/bin/sh
# leakgate installer.
# Usage: curl -fsSL https://raw.githubusercontent.com/ayushrajdev-dev/leakgate/main/install.sh | sh
set -eu

REPO="ayushrajdev-dev/leakgate"
BIN="leakgate"

version="${LEAKGATE_VERSION:-latest}"
if [ "$version" = "latest" ]; then
    url="https://api.github.com/repos/${REPO}/releases/latest"
else
    url="https://api.github.com/repos/${REPO}/releases/tags/${version}"
fi

os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
    Linux)  os_part="linux" ;;
    Darwin) os_part="macos" ;;
    *)
        echo "Unsupported OS: $os. Build from source: cargo install --git https://github.com/${REPO}" >&2
        exit 1
        ;;
esac

case "$arch" in
    x86_64|amd64) arch_part="x86_64" ;;
    arm64|aarch64) arch_part="aarch64" ;;
    *)
        echo "Unsupported architecture: $arch. Build from source: cargo install --git https://github.com/${REPO}" >&2
        exit 1
        ;;
esac

asset="${BIN}-${os_part}-${arch_part}.tar.gz"

if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -qO- "$1"; }
else
    echo "Need curl or wget." >&2
    exit 1
fi

tag="$(fetch "$url" | grep '"tag_name"' | head -n1 | cut -d'"' -f4)"
if [ -z "$tag" ]; then
    echo "Could not resolve a release. Build from source: cargo install --git https://github.com/${REPO}" >&2
    exit 1
fi

download="https://github.com/${REPO}/releases/download/${tag}/${asset}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading ${asset} (${tag})"
fetch "$download" > "${tmp}/${asset}" || {
    echo "No binary for ${os_part}/${arch_part}. Build from source: cargo install --git https://github.com/${REPO}" >&2
    exit 1
}

tar -xzf "${tmp}/${asset}" -C "$tmp"
chmod +x "${tmp}/${BIN}"

dir="${LEAKGATE_DIR:-}"
if [ -z "$dir" ]; then
    if [ -w /usr/local/bin ]; then
        dir="/usr/local/bin"
    else
        dir="${HOME}/.local/bin"
    fi
fi
mkdir -p "$dir"

if command -v install >/dev/null 2>&1; then
    install -m 0755 "${tmp}/${BIN}" "${dir}/${BIN}"
else
    cp "${tmp}/${BIN}" "${dir}/${BIN}"
    chmod 0755 "${dir}/${BIN}"
fi

echo "Installed ${BIN} ${tag} to ${dir}/${BIN}"
case ":$PATH:" in
    *":${dir}:"*) ;;
    *) echo "Add ${dir} to PATH to run ${BIN}." ;;
esac
