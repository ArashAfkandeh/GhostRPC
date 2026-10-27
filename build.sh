#!/bin/bash
# GhostRPC Auto Build Script

set -e
export DEBIAN_FRONTEND=noninteractive

echo "==========================================="
echo "   GhostRPC Auto Build Script              "
echo "==========================================="

# Go to script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 1. Update and install basic dependencies
echo "[*] Checking and installing basic build dependencies..."

NEEDS_RUST=false
if ! command -v cargo &> /dev/null; then
    NEEDS_RUST=true
fi

if command -v apt-get &> /dev/null; then
    MISSING=""
    for pkg in curl build-essential pkg-config libssl-dev; do
        if ! dpkg -l | grep -qw "^ii  $pkg"; then
            MISSING="$MISSING $pkg"
        fi
    done
    
    if [ -n "$MISSING" ] || [ "$NEEDS_RUST" = true ]; then
        echo "[*] Installing missing dependencies... (apt update)"
        sudo DEBIAN_FRONTEND=noninteractive apt-get update -yq
        if [ -n "$MISSING" ]; then
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -yq $MISSING
        fi
    else
        echo "[*] All apt dependencies are already installed."
    fi
elif command -v yum &> /dev/null; then
    if [ "$NEEDS_RUST" = true ]; then sudo yum update -y; fi
    sudo yum groupinstall -y "Development Tools"
    sudo yum install -y curl openssl-devel
elif command -v dnf &> /dev/null; then
    if [ "$NEEDS_RUST" = true ]; then sudo dnf update -y; fi
    sudo dnf groupinstall -y "Development Tools"
    sudo dnf install -y curl openssl-devel
elif command -v pacman &> /dev/null; then
    sudo pacman -Sy --noconfirm base-devel curl openssl
else
    echo "[!] Unsupported package manager. Please install build essentials and OpenSSL manually."
fi

# 2. Check and install Rust/Cargo
if ! command -v cargo &> /dev/null; then
    echo "[*] Rust (Cargo) is not installed. Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    
    # Source the environment variables for the current session
    export PATH="$HOME/.cargo/bin:$PATH"
    echo "[*] Rust has been successfully installed."
else
    echo "[*] Rust is already installed: $(cargo --version)"
fi

# 3. Build the project
echo "[*] Building GhostRPC for release..."
# Ensure we are in the directory containing Cargo.toml
if [ ! -f "Cargo.toml" ]; then
    echo "[!] Cargo.toml not found in the current directory! Please run this script from the root of the project."
    exit 1
fi

# 3a. Web admin panel: the UI files in ./panel are embedded into the binary at compile time
# (include_str!/include_bytes!), so no separate frontend build step or Node.js is needed.
echo "[*] Checking web panel assets (./panel)..."
PANEL_FILES="index.html login.html app.css i18n.js favicon.svg fonts/vazirmatn.woff2 modules/core.js modules/login.js modules/dashboard.js modules/tunnels.js modules/connections.js modules/logs.js modules/config.js modules/certs.js modules/account.js"
PANEL_MISSING=""
for f in $PANEL_FILES; do
    if [ ! -s "panel/$f" ]; then
        PANEL_MISSING="$PANEL_MISSING panel/$f"
    fi
done
if [ -n "$PANEL_MISSING" ]; then
    echo "[!] Missing or empty web panel files:$PANEL_MISSING"
    echo "    The panel is compiled into the binary, so the build cannot continue without them."
    exit 1
fi

# The Settings guide serves these sanitized example configurations from the binary.
CONFIG_SAMPLES="client.toml server.toml"
CONFIG_SAMPLES_MISSING=""
for f in $CONFIG_SAMPLES; do
    if [ ! -s "$f" ]; then
        CONFIG_SAMPLES_MISSING="$CONFIG_SAMPLES_MISSING $f"
    fi
done
if [ -n "$CONFIG_SAMPLES_MISSING" ]; then
    echo "[!] Missing or empty embedded configuration samples:$CONFIG_SAMPLES_MISSING"
    echo "    The Settings guide is compiled into the binary and requires both sample files."
    exit 1
fi

# Optional: catch JavaScript syntax errors early when Node.js happens to be installed.
if command -v node &> /dev/null; then
    for js in i18n.js modules/core.js modules/login.js modules/dashboard.js modules/tunnels.js modules/connections.js modules/logs.js modules/config.js modules/certs.js modules/account.js; do
        node --check "panel/$js" || { echo "[!] Syntax error in panel/$js"; exit 1; }
    done
    echo "[*] Web panel JavaScript syntax OK."
fi

# 3b. Compile (the panel is built in together with the tunnel)
RUSTFLAGS="-C target-cpu=generic" CARGO_TARGET_DIR=/root/target cargo build --release
rm -f ./GhostRPC
cp /root/target/release/GhostRPC ./GhostRPC
echo "✅ Build Completed Successfully!"
echo ""
echo "[*] Quick Instructions:"
echo "    Server Mode: ./GhostRPC server.toml"
echo "    Client Mode: ./GhostRPC client.toml"
echo ""
echo "[+] The executable is located at: ./GhostRPC"
echo "==========================================="
