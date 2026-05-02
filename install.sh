#!/usr/bin/env bash
set -euo pipefail

BINARY_NAME="void"
INSTALL_DIR="$HOME/.local/bin"
DESKTOP_DIR="$HOME/.local/share/applications"
BINARY_PATH="$INSTALL_DIR/$BINARY_NAME"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }

check_cmd() {
    command -v "$1" &>/dev/null
}

# ── Detect package manager ────────────────────────────────────────────────────
detect_distro() {
    if check_cmd apt; then echo "apt"
    elif check_cmd dnf; then echo "dnf"
    elif check_cmd pacman; then echo "pacman"
    else echo "unknown"
    fi
}

# ── Check system dependencies ─────────────────────────────────────────────────
check_deps() {
    info "Checking system dependencies..."

    local missing=()

    # Check pkg-config
    check_cmd pkg-config || missing+=("pkg-config")

    # Check GTK3
    pkg-config --exists gtk+-3.0 2>/dev/null || missing+=("libgtk-3-dev")

    # Check WebKit2GTK
    pkg-config --exists webkit2gtk-4.1 2>/dev/null || missing+=("libwebkit2gtk-4.1-dev")

    # Check libsoup3
    pkg-config --exists libsoup-3.0 2>/dev/null || missing+=("libsoup-3.0-dev")

    # Check tor
    check_cmd tor || warn "tor not found — Tor mode will not be available"

    if [ ${#missing[@]} -gt 0 ]; then
        warn "Missing dependencies: ${missing[*]}"
        local distro
        distro=$(detect_distro)
        case "$distro" in
            apt)
                echo ""
                echo "Install with:"
                echo "  sudo apt install build-essential pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev libsoup-3.0-dev tor"
                ;;
            dnf)
                echo ""
                echo "Install with:"
                echo "  sudo dnf install gcc pkg-config gtk3-devel webkit2gtk4.1-devel libsoup3-devel tor"
                ;;
            pacman)
                echo ""
                echo "Install with:"
                echo "  sudo pacman -S base-devel gtk3 webkit2gtk-4.1 libsoup3 tor"
                ;;
            *)
                echo ""
                echo "Please install the missing dependencies for your distribution."
                ;;
        esac
        echo ""
        read -rp "Continue anyway? [y/N] " yn
        [[ "$yn" =~ ^[Yy]$ ]] || exit 1
    else
        success "All dependencies found"
    fi
}

# ── Check Rust toolchain ──────────────────────────────────────────────────────
check_rust() {
    info "Checking Rust toolchain..."
    if ! check_cmd cargo; then
        warn "Rust not found. Installing via rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
        source "$HOME/.cargo/env"
        check_cmd cargo || error "Rust installation failed"
    fi
    success "Rust $(rustc --version | cut -d' ' -f2) found"
}

# ── Build ─────────────────────────────────────────────────────────────────────
build() {
    info "Building void (release)..."
    cargo build --release 2>&1 | tail -5
    [ -f "target/release/$BINARY_NAME" ] || error "Build failed — binary not found"
    success "Build complete"
}

# ── Install binary ────────────────────────────────────────────────────────────
install_binary() {
    info "Installing binary to $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR"
    cp "target/release/$BINARY_NAME" "$BINARY_PATH"
    chmod +x "$BINARY_PATH"
    success "Binary installed: $BINARY_PATH"

    # Warn if not in PATH
    if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
        warn "$INSTALL_DIR is not in your PATH"
        echo "  Add to ~/.bashrc or ~/.zshrc:"
        echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
}

# ── Desktop entry ─────────────────────────────────────────────────────────────
install_desktop() {
    info "Installing desktop entry..."
    mkdir -p "$DESKTOP_DIR"
    cat > "$DESKTOP_DIR/void.desktop" <<EOF
[Desktop Entry]
Name=Void
Comment=Privacy-focused browser with Tor integration
Exec=$BINARY_PATH %u
Terminal=false
Type=Application
Categories=Network;WebBrowser;
Keywords=browser;privacy;tor;anonymous;
StartupNotify=true
EOF
    success "Desktop entry installed: $DESKTOP_DIR/void.desktop"
}

# ── Uninstall ─────────────────────────────────────────────────────────────────
uninstall() {
    info "Uninstalling void..."
    rm -f "$BINARY_PATH"
    rm -f "$DESKTOP_DIR/void.desktop"
    success "Uninstalled"
    warn "Config at ~/.config/void/ was not removed"
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    echo ""
    echo "  void browser installer"
    echo "  ─────────────────────"
    echo ""

    case "${1:-install}" in
        install)
            check_deps
            check_rust
            build
            install_binary
            install_desktop
            echo ""
            success "void installed successfully"
            echo ""
            echo "  Run:        void"
            echo "  Tor mode:   void --tor"
            echo "  New tab:    + button in toolbar"
            echo "  New ID:     🔄 button (fresh isolated context)"
            echo ""
            ;;
        uninstall)
            uninstall
            ;;
        build-only)
            check_rust
            build
            echo ""
            success "Binary at: target/release/void"
            ;;
        *)
            echo "Usage: $0 [install|uninstall|build-only]"
            exit 1
            ;;
    esac
}

main "$@"
