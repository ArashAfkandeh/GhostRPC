#!/bin/bash
# GhostRPC Auto Installation Script

echo "==========================================="
echo "        GhostRPC Tunnel Installer          "
echo "==========================================="
echo ""

echo "[*] Installing required dependencies..."
sudo apt-get update -y
sudo apt-get install -y curl wget tar

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

echo "[*] Starting GhostRPC service..."
chmod +x /root/GhostRPC/GhostRPC
systemctl daemon-reload
systemctl enable GhostRPC.service
systemctl start GhostRPC.service

echo "[*] Setting up CLI Manager..."
chmod +x /root/GhostRPC/ghostrpc.sh
ln -sf /root/GhostRPC/ghostrpc.sh /usr/local/bin/ghostrpc

echo -e "\n\033[0;32m✅ GhostRPC installation completed successfully!\033[0m"
echo -e "\033[0;33m💡 Thanks to Hot-Reload, you can edit your configs anytime after installation without restarting!\033[0m"
echo -e "\033[0;36m========================================================================\033[0m"
echo -e "To manage your service, simply type the following command from anywhere:"
echo -e "\n    \033[1;35mghostrpc\033[0m\n"
echo -e "\033[0;36m========================================================================\033[0m"
