#!/usr/bin/env bash
# ©AngelaMos | 2026
# install.sh
#
# One-shot installer for corvus. Goes from a fresh machine to `corvus` on your
# PATH with the intelligence database seeded. Run it from a clone:
#
#   ./install.sh
#
# Pass --live to also grant the raw-socket capabilities live capture needs.

set -euo pipefail

# ============================================================================
# Config
# ============================================================================
REPO_OWNER="CarterPerez-dev"
REPO_NAME="Cybersecurity-Projects"
SUBDIR="PROJECTS/intermediate/ja3-ja4-tls-fingerprinting"
BINARY="corvus"
CRATE="crates/corvus"
REPO_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}.git"
DEFAULT_BRANCH="main"

JA4DB_URL="${JA4DB_URL:-https://ja4db.com/api/read/}"
JA4DB_TIMEOUT="${JA4DB_TIMEOUT:-180}"

PREFIX="${CORVUS_PREFIX:-}"      # cargo install --root; empty = cargo's default (~/.cargo/bin)
DO_LIVE=0

# ============================================================================
# Colors (gated so `| bash`, logs, and CI stay clean)
# ============================================================================
if [ -t 2 ] && [ -z "${NO_COLOR:-}" ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'
    YELLOW=$'\033[33m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
else
    BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; CYAN=""; RESET=""
fi

info() { printf '%s\n' "  ${CYAN}+${RESET} $*" >&2; }
ok()   { printf '%s\n' "  ${GREEN}+${RESET} $*" >&2; }
warn() { printf '%s\n' "  ${YELLOW}!${RESET} $*" >&2; }
die()  { printf '%s\n' "  ${RED}x $*${RESET}" >&2; exit 1; }
header(){ printf '\n%s\n\n' "${BOLD}${CYAN}--- $* ---${RESET}" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

trap 'printf "%s\n" "${RED}x install failed${RESET}" >&2' ERR
TMP_DIR=""
cleanup() { [ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR"; return 0; }
trap cleanup EXIT

banner() {
    printf '%s' "${CYAN}${BOLD}" >&2
    cat >&2 <<'ART'

   ___ ___  _____   ___   _ ___
  / __/ _ \| _ \ \ / / | | / __|
 | (_| (_) |   /\ V /| |_| \__ \
  \___\___/|_|_\ \_/  \__,_|___/
ART
    printf '%s\n' "${RESET}" >&2
    printf '%s\n' "  ${DIM}JA3/JA4 TLS fingerprinting, intel matching, anomaly detection${RESET}" >&2
}

# ============================================================================
# Privilege + package-manager fan
# ============================================================================
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if have sudo; then SUDO="sudo"; fi
fi

pkg_install() {   # best-effort multi-distro install of the given package names
    if   have apt-get; then $SUDO apt-get update -y >/dev/null 2>&1 || warn "apt update had errors (often unrelated repos); continuing"
                            $SUDO apt-get install -y --no-install-recommends "$@"
    elif have dnf;     then $SUDO dnf install -y "$@"
    elif have pacman;  then $SUDO pacman -S --needed --noconfirm "$@"
    elif have zypper;  then $SUDO zypper install -y "$@"
    elif have apk;     then $SUDO apk add "$@"
    elif have brew;    then brew install "$@"
    else return 1; fi
}

download() {   # download URL DEST
    if   have curl; then curl -fsSL --max-time "$JA4DB_TIMEOUT" "$1" -o "$2"
    elif have wget; then wget -q --timeout="$JA4DB_TIMEOUT" -O "$2" "$1"
    else return 1; fi
}

# ============================================================================
# Args
# ============================================================================
usage() {
    cat >&2 <<USAGE
install.sh — install corvus

  ./install.sh [options]

options:
  --live          also grant live-capture capabilities (uses sudo setcap)
  --prefix DIR    install root (binary lands in DIR/bin; default: ~/.cargo/bin)
  -h, --help      this help

env overrides:
  JA4DB_URL, JA4DB_TIMEOUT   enrichment feed source and download timeout
USAGE
}
while [ $# -gt 0 ]; do
    case "$1" in
        --live) DO_LIVE=1; shift ;;
        --prefix) PREFIX="$2"; shift 2 ;;
        --prefix=*) PREFIX="${1#*=}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

# ============================================================================
# OS / arch
# ============================================================================
OS="$(uname -s)"; ARCH="$(uname -m)"
case "$OS" in
    Linux) OS="linux" ;;
    Darwin) OS="darwin" ;;
    MINGW*|MSYS*|CYGWIN*) die "Windows is not supported. Use WSL2." ;;
    *) die "unsupported OS: $OS" ;;
esac
case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) die "unsupported architecture: $ARCH" ;;
esac

# ============================================================================
# Bootstrap: locate the project, cloning the monorepo if piped from the web
# ============================================================================
resolve_project() {
    if [ -f "./Cargo.toml" ] && [ -d "./crates/corvus" ]; then
        pwd; return
    fi
    local self="${BASH_SOURCE[0]:-}"
    if [ -n "$self" ] && [ -f "$(dirname "$self")/Cargo.toml" ] && [ -d "$(dirname "$self")/crates/corvus" ]; then
        (cd "$(dirname "$self")" && pwd); return
    fi
    have git || { warn "git not found — installing it"; pkg_install git || die "could not install git; install it then re-run"; }
    have git || die "git is required to bootstrap corvus"
    local cache="${XDG_CACHE_HOME:-$HOME/.cache}/corvus-src"
    if [ -d "$cache/.git" ]; then
        info "updating cached clone at $cache"
        git -C "$cache" pull --ff-only --quiet 2>/dev/null || warn "pull failed; using existing clone"
    else
        info "cloning ${REPO_NAME}"
        git clone --depth 1 --branch "$DEFAULT_BRANCH" --filter=blob:none --quiet "$REPO_URL" "$cache" \
            || die "clone failed from ${REPO_URL}"
    fi
    printf '%s\n' "$cache/$SUBDIR"
}

# ============================================================================
# Rust toolchain
# ============================================================================
ensure_rust() {
    if ! have cargo; then
        info "Rust not found — installing via rustup"
        if have curl; then
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path >&2
        elif have wget; then
            wget -qO- https://sh.rustup.rs | sh -s -- -y --no-modify-path >&2
        else
            die "need curl or wget to install Rust (or install it from https://rustup.rs)"
        fi
        # shellcheck disable=SC1091
        . "${CARGO_HOME:-$HOME/.cargo}/env"
    fi
    have cargo || die "cargo still not on PATH after install; open a new shell and re-run"
    ok "cargo $(cargo --version | awk '{print $2}')"
}

# ============================================================================
# System build dependencies (libpcap + a C toolchain for bundled SQLite)
# ============================================================================
ensure_build_deps() {
    # Only act if something is actually missing, so we never sudo for no reason.
    local cc_ok=0 pcap_ok=0
    if have cc || have gcc || have clang; then cc_ok=1; fi
    if [ -e /usr/include/pcap/pcap.h ] || [ -e /usr/include/pcap.h ] || [ -e /opt/homebrew/include/pcap/pcap.h ]; then pcap_ok=1; fi

    if [ "$OS" = "darwin" ]; then
        if [ "$pcap_ok" -eq 0 ]; then
            pkg_install libpcap pkg-config || warn "could not install libpcap via brew; build may fail"
        fi
        return
    fi

    if [ "$pcap_ok" -eq 0 ] || [ "$cc_ok" -eq 0 ]; then
        info "installing build dependencies (libpcap headers + C toolchain)"
        if   have apt-get; then pkg_install libpcap-dev pkg-config build-essential
        elif have dnf;     then pkg_install libpcap-devel pkgconf-pkg-config gcc make
        elif have pacman;  then pkg_install libpcap pkgconf base-devel
        elif have zypper;  then pkg_install libpcap-devel pkg-config gcc make
        elif have apk;     then pkg_install libpcap-dev pkgconfig build-base
        else warn "unknown package manager — ensure libpcap headers and a C compiler are installed"; fi
    fi
}

# ============================================================================
# Build + install onto PATH
# ============================================================================
CARGO_BIN_DIR="${CARGO_HOME:-$HOME/.cargo}/bin"
install_binary() {
    header "Building and installing corvus"
    if [ -n "$PREFIX" ]; then
        cargo install --path "$CRATE" --root "$PREFIX" --force >&2
        CARGO_BIN_DIR="$PREFIX/bin"
    else
        cargo install --path "$CRATE" --force >&2
    fi
    ok "installed ${BINARY} -> ${CARGO_BIN_DIR}/${BINARY}"
}

wire_path() {
    case ":$PATH:" in *":$CARGO_BIN_DIR:"*) ok "$CARGO_BIN_DIR already on PATH"; return ;; esac
    local shell rc=""
    shell="$(basename "${SHELL:-bash}")"
    case "$shell" in
        zsh)  rc="$HOME/.zshrc" ;;
        fish) mkdir -p "$HOME/.config/fish/conf.d"
              echo "fish_add_path $CARGO_BIN_DIR" > "$HOME/.config/fish/conf.d/corvus.fish"
              ok "added $CARGO_BIN_DIR to PATH (fish)" ;;
        bash) rc="$HOME/.bashrc"; [ -f "$rc" ] || rc="$HOME/.bash_profile" ;;
        *)    rc="$HOME/.profile" ;;
    esac
    if [ -n "$rc" ] && ! grep -q "$CARGO_BIN_DIR" "$rc" 2>/dev/null; then
        printf '\nexport PATH="%s:$PATH"\n' "$CARGO_BIN_DIR" >> "$rc"
        ok "added $CARGO_BIN_DIR to PATH in $rc"
    fi
    export PATH="$CARGO_BIN_DIR:$PATH"
}

# ============================================================================
# Seed the intelligence database
# ============================================================================
seed_intel() {
    header "Seeding the intelligence database"
    info "loading the bundled feeds (abuse.ch SSLBL, salesforce/ja3, curated C2)"
    "$BINARY" intel seed >&2
    ok "bundled feeds loaded"

    info "fetching the ja4db.com enrichment feed"
    if ! have curl && ! have wget; then
        warn "no curl/wget; skipping ja4db. The bundled feeds still work."
        return
    fi
    TMP_DIR="$(mktemp -d)"
    if download "$JA4DB_URL" "$TMP_DIR/ja4db.json"; then
        "$BINARY" intel import "$TMP_DIR/ja4db.json" >&2 && ok "ja4db imported"
    else
        warn "could not reach ${JA4DB_URL} (large and often slow); bundled feeds still work."
        warn "retry later:  ${BINARY} intel import <(curl -fsSL ${JA4DB_URL})"
    fi
}

# ============================================================================
# Live-capture capabilities
# ============================================================================
grant_live() {
    header "Enabling live capture"
    if [ "$OS" = "darwin" ]; then
        warn "setcap is Linux-only; on macOS run live capture under sudo:  sudo ${BINARY} live <iface>"
        return
    fi
    if ! have setcap; then
        info "installing setcap (libcap)"
        if   have apt-get; then pkg_install libcap2-bin
        elif have dnf || have zypper; then pkg_install libcap
        elif have pacman;  then pkg_install libcap
        elif have apk;     then pkg_install libcap
        fi
    fi
    local bin; bin="$(command -v "$BINARY")"
    if have setcap && $SUDO setcap cap_net_raw,cap_net_admin=eip "$bin"; then
        ok "live capture enabled for $bin (no sudo needed to run ${BINARY} live)"
    else
        warn "setcap unavailable; run live capture under sudo, or grant later:"
        warn "  sudo setcap cap_net_raw,cap_net_admin=eip \"\$(command -v ${BINARY})\""
    fi
}

# ============================================================================
# Main
# ============================================================================
banner
have "$BINARY" && info "existing install at $(command -v "$BINARY") — updating"

PROJECT="$(resolve_project)"
cd "$PROJECT"
ensure_rust
ensure_build_deps
install_binary
wire_path
seed_intel
[ "$DO_LIVE" -eq 1 ] && grant_live

header "Verify"
if have "$BINARY"; then
    ok "$($BINARY --version 2>/dev/null || echo "$BINARY installed")"
else
    warn "installed to $CARGO_BIN_DIR but not yet on this shell's PATH"
    warn "open a new terminal, or: export PATH=\"$CARGO_BIN_DIR:\$PATH\""
fi

printf '\n%s\n\n' "  ${GREEN}${BOLD}corvus is ready.${RESET}" >&2
cat >&2 <<FOOTER
  ${DIM}fingerprint a capture:${RESET}   ${CYAN}${BINARY} pcap --intel capture.pcap${RESET}
  ${DIM}fingerprint live:${RESET}        ${CYAN}${BINARY} live --intel any${RESET}
  ${DIM}detect anomalies:${RESET}        ${CYAN}${BINARY} live --detect any${RESET}
  ${DIM}inspect the intel db:${RESET}    ${CYAN}${BINARY} intel stats${RESET}
  ${DIM}look one up:${RESET}             ${CYAN}${BINARY} intel lookup ja3 <hash>${RESET}
FOOTER
if [ "$DO_LIVE" -eq 0 ]; then
    printf '%s\n' "  ${DIM}live capture needs caps (then NO sudo):${RESET}  re-run ${CYAN}install.sh --live${RESET}" >&2
    printf '%s\n' "  ${DIM}or grant now:${RESET}  ${CYAN}sudo setcap cap_net_raw,cap_net_admin=eip \"\$(command -v corvus)\"${RESET}" >&2
fi
have just && [ -f "$PROJECT/justfile" ] && printf '%s\n' "  ${DIM}dev commands:${RESET}            ${CYAN}just${RESET}" >&2
printf '%s\n' "  ${DIM}docs: https://github.com/${REPO_OWNER}/${REPO_NAME}${RESET}" >&2
