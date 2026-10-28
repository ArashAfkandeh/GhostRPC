#!/bin/bash
# GhostRPC Auto Installation Script

echo "==========================================="
echo "        GhostRPC Tunnel Installer          "
echo "==========================================="
echo ""

echo "[*] Installing required dependencies..."
if ! sudo apt-get update -y || ! sudo apt-get install -y curl wget tar iproute2; then
    echo "❌ Failed to install required dependencies."
    exit 1
fi

if ! command -v ss >/dev/null 2>&1; then
    echo "❌ The ss utility is required to check whether ports are available."
    exit 1
fi

GITHUB_REPO="https://github.com/ArashAfkandeh/GhostRPC/releases/latest/download/GhostRPC.tar.gz"

echo "[*] Downloading GhostRPC from GitHub..."
wget -qO /root/GhostRPC.tar.gz "$GITHUB_REPO" || curl -sL -o /root/GhostRPC.tar.gz "$GITHUB_REPO"

if [ ! -f "/root/GhostRPC.tar.gz" ]; then
    echo "❌ Failed to download GhostRPC.tar.gz. Please check the URL in the script."
    exit 1
fi

echo "[*] Extracting GhostRPC..."
mkdir -p /root/GhostRPC
sudo tar -xzvf /root/GhostRPC.tar.gz -C /root/GhostRPC --strip-components=1

echo ""
echo "Select installation mode:"
echo "1) Server Mode"
echo "2) Client Mode"
read -p "Enter your choice (1 or 2): " mode_choice </dev/tty

SERVICE_FILE="/etc/systemd/system/GhostRPC.service"

if [ "$mode_choice" == "1" ]; then
    echo "[*] Installing GhostRPC as Server..."
    CONFIG_FILE="/root/GhostRPC/server.toml"
    tee $SERVICE_FILE > /dev/null << 'EOL'
[Unit]
Description=GhostRPC Tunnel Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/GhostRPC
ExecStart=/root/GhostRPC/GhostRPC /root/GhostRPC/server.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576
LimitNPROC=1048576

[Install]
WantedBy=multi-user.target
EOL

elif [ "$mode_choice" == "2" ]; then
    echo "[*] Installing GhostRPC as Client..."
    CONFIG_FILE="/root/GhostRPC/client.toml"
    tee $SERVICE_FILE > /dev/null << 'EOL'
[Unit]
Description=GhostRPC Tunnel Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/GhostRPC
ExecStart=/root/GhostRPC/GhostRPC /root/GhostRPC/client.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576
LimitNPROC=1048576

[Install]
WantedBy=multi-user.target
EOL

else
    echo "❌ Invalid choice! Exiting."
    exit 1
fi

is_valid_domain() {
    local domain="$1"
    local label

    [[ ${#domain} -le 253 ]] || return 1
    [[ "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]] || return 1

    IFS='.' read -r -a labels <<< "$domain"
    for label in "${labels[@]}"; do
        [[ ${#label} -le 63 ]] || return 1
    done
}

port_in_use() {
    ss -H -ltn "sport = :$1" 2>/dev/null | grep -q .
}

set_admin_port() {
    sed -i "/^\\[admin\\]/,/^\\[/{s/^\\(bind_addr = \".*:\\)[0-9]\\+\"/\\1$2\"/;}" "$1"
}

echo ""
while true; do
    read -r -p "Enter the panel domain/subdomain (without https://): " panel_domain </dev/tty
    if is_valid_domain "$panel_domain"; then
        break
    fi
    echo "❌ Enter a valid domain name, for example panel.example.com."
done

if [ "$mode_choice" == "1" ]; then
    PANEL_PORT=$(awk '
        /^\[server\][[:space:]]*$/ { in_server = 1; next }
        /^\[/ { if (in_server) exit; in_server = 0 }
        in_server && /^[[:space:]]*bind_addr[[:space:]]*=/ {
            gsub(/"/, "", $3)
            count = split($3, parts, ":")
            print parts[count]
            exit
        }
    ' "$CONFIG_FILE")
else
    PANEL_PORT=443
fi

if ! [[ "$PANEL_PORT" =~ ^[0-9]+$ ]] || [ "$PANEL_PORT" -lt 1 ] || [ "$PANEL_PORT" -gt 65535 ]; then
    echo "❌ Could not determine a valid HTTPS listener port from $CONFIG_FILE."
    exit 1
fi

if port_in_use "$PANEL_PORT"; then
    echo "❌ HTTPS port $PANEL_PORT is already in use. Free that port before installing GhostRPC."
    exit 1
fi

ADMIN_PORT=8088
while port_in_use "$ADMIN_PORT"; do
    if [ "$ADMIN_PORT" -ge 65535 ]; then
        echo "❌ No free admin panel port was found starting at 8088."
        exit 1
    fi
    ADMIN_PORT=$((ADMIN_PORT + 1))
done

for config in /root/GhostRPC/server.toml /root/GhostRPC/client.toml; do
    if [ ! -f "$config" ]; then
        echo "❌ Configuration file not found: $config"
        exit 1
    fi
    sed -i "s/panel\\.example\\.com/$panel_domain/g" "$config"
    set_admin_port "$config" "$ADMIN_PORT"
done

echo "[*] Panel domain set to $panel_domain (HTTPS port $PANEL_PORT)."
echo "[*] Admin panel will use 127.0.0.1:$ADMIN_PORT."
PANEL_URL="http://$panel_domain"
if [ "$PANEL_PORT" != "443" ]; then
    PANEL_URL="$PANEL_URL:$PANEL_PORT"
fi

echo "[*] Starting GhostRPC service..."
chmod +x /root/GhostRPC/GhostRPC
if ! systemctl daemon-reload || ! systemctl enable GhostRPC.service || ! systemctl start GhostRPC.service; then
    echo "❌ Failed to configure or start GhostRPC.service."
    exit 1
fi

if ! systemctl is-active --quiet GhostRPC.service; then
    echo "❌ GhostRPC.service did not become active. Check: journalctl -u GhostRPC.service"
    exit 1
fi

echo "[*] Setting up CLI Manager..."
chmod +x /root/GhostRPC/ghostrpc.sh
ln -sf /root/GhostRPC/ghostrpc.sh /usr/local/bin/ghostrpc

echo -e "\n\033[0;32m✅ GhostRPC installation completed successfully!\033[0m"
echo -e "🌐 Panel: \033[0;32m$PANEL_URL\033[0m"
echo -e "👤 Username: \033[0;36madmin\033[0m"
echo -e "🔑 Password: \033[0;36madmin\033[0m"
echo -e "\033[0;33m⚠️ Change the default panel credentials after your first login.\033[0m"
echo -e "\033[0;33m💡 Thanks to Hot-Reload, you can edit your configs anytime after installation without restarting!\033[0m"
echo -e "\033[0;36m========================================================================\033[0m"
echo -e "To manage your service, simply type the following command from anywhere:"
echo -e "\n    \033[1;35mghostrpc\033[0m\n"
echo -e "\033[0;36m========================================================================\033[0m"
