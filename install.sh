#!/usr/bin/env bash
set -euo pipefail

# void installer — made by Ivoryy06 ♡
# Installs void for the current user only. Never changes the default browser.

BINARY_NAME="void"
INSTALL_DIR="$HOME/.local/bin"
DESKTOP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"
BINARY_PATH="$INSTALL_DIR/$BINARY_NAME"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[x]${NC} $1"; exit 1; }
success() { echo -e "${GREEN}[ok]${NC} $1"; }

check_cmd() {
    command -v "$1" &>/dev/null
}

detect_distro() {
    if check_cmd apt; then echo "apt"
    elif check_cmd dnf; then echo "dnf"
    elif check_cmd pacman; then echo "pacman"
    else echo "unknown"
    fi
}

check_deps() {
    info "Checking system dependencies..."

    local missing=()

    check_cmd pkg-config || missing+=("pkg-config")
    pkg-config --exists gtk+-3.0 2>/dev/null || missing+=("libgtk-3-dev")
    pkg-config --exists webkit2gtk-4.1 2>/dev/null || missing+=("libwebkit2gtk-4.1-dev")
    pkg-config --exists libsoup-3.0 2>/dev/null || missing+=("libsoup-3.0-dev")

    check_cmd tor || warn "tor not found — Tor mode will not be available"

    if [ ${#missing[@]} -gt 0 ]; then
        warn "Missing dependencies: ${missing[*]}"
        case "$(detect_distro)" in
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

check_rust() {
    info "Checking Rust toolchain..."
    if ! check_cmd cargo; then
        warn "Rust not found. Installing via rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
        # shellcheck disable=SC1091
        source "$HOME/.cargo/env"
        check_cmd cargo || error "Rust installation failed"
    fi
    success "Rust $(rustc --version | cut -d' ' -f2) found"
}

build() {
    info "Building void (release)..."
    cargo build --release 2>&1 | tail -5
    [ -f "target/release/$BINARY_NAME" ] || error "Build failed — binary not found"
    success "Build complete"
}

install_binary() {
    info "Installing binary to $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR"
    cp "target/release/$BINARY_NAME" "$BINARY_PATH"
    chmod +x "$BINARY_PATH"
    success "Binary installed: $BINARY_PATH"

    if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
        warn "$INSTALL_DIR is not in your PATH"
        echo "  Add this to ~/.bashrc or ~/.zshrc:"
        echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
}

install_icon() {
    if [ -f "assets/void.svg" ]; then
        info "Installing icon..."
        mkdir -p "$ICON_DIR"
        cp "assets/void.svg" "$ICON_DIR/void.svg"
        command -v gtk-update-icon-cache &>/dev/null \
            && gtk-update-icon-cache -f -t "$HOME/.local/share/icons/hicolor" &>/dev/null || true
        success "Icon installed"
    else
        warn "assets/void.svg missing — using a stock icon"
    fi
}

install_desktop() {
    info "Installing desktop entry..."
    mkdir -p "$DESKTOP_DIR"
    cat > "$DESKTOP_DIR/void.desktop" <<EOF
[Desktop Entry]
Name=void
Comment=Quiet private browser with Tor and ephemeral tabs
Exec=$BINARY_PATH %u
Icon=void
Terminal=false
Type=Application
Categories=Network;WebBrowser;
Keywords=browser;privacy;tor;anonymous;
StartupNotify=true
StartupWMClass=void
Actions=Tor;

[Desktop Action Tor]
Name=Open with Tor
Exec=$BINARY_PATH --tor
EOF
    # Deliberately no MimeType line: void does not claim to be a default browser.
    success "Desktop entry installed: $DESKTOP_DIR/void.desktop"
}

uninstall() {
    info "Uninstalling void..."
    rm -f "$BINARY_PATH"
    rm -f "$DESKTOP_DIR/void.desktop"
    rm -f "$ICON_DIR/void.svg"
    success "Binary, desktop entry and icon removed"
    warn "Config at ~/.config/void/ was left alone"
}

main() {
    echo ""
    echo "  void installer"
    echo "  ──────────────"
    echo "  made by Ivoryy06 ♡"
    echo ""

    case "${1:-install}" in
        install)
            check_deps
            check_rust
            build
            install_binary
            install_icon
            install_desktop
            echo ""
            success "void installed"
            echo ""
            echo "  Run:        void"
            echo "  Tor mode:   void --tor"
            echo "  New tab:    + (isolated context)"
            echo "  New id:     fresh session and circuits"
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
