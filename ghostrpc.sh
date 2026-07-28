#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

SERVICE_FILE="/etc/systemd/system/GhostRPC.service"
APP_DIR="/root/GhostRPC"
BIN_PATH="$APP_DIR/GhostRPC"
REPO_URL="https://github.com/ArashAfkandeh/GhostRPC/releases/latest/download/GhostRPC.tar.gz"

function get_status() {
    if systemctl is-active --quiet GhostRPC.service; then
        echo -e "${GREEN}Active${NC}"
    else
        echo -e "${RED}Inactive${NC}"
    fi
}

function start_service() {
    if [ ! -f "$SERVICE_FILE" ]; then
        echo -e "${YELLOW}Service file not found. Creating it now...${NC}"
        echo "Select mode:"
        echo "1) Server Mode"
        echo "2) Client Mode"
        read -p "Choice (1 or 2): " mode
        
        if [ "$mode" == "1" ]; then
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
        elif [ "$mode" == "2" ]; then
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
            echo -e "${RED}Invalid choice! Cancelled.${NC}"
            return
        fi
        
        systemctl daemon-reload
        systemctl enable GhostRPC.service
    fi
    
    echo -e "${CYAN}Starting GhostRPC...${NC}"
    systemctl start GhostRPC.service
    echo -e "${GREEN}Service Started.${NC}"
}

function stop_service() {
    echo -e "${CYAN}Stopping GhostRPC...${NC}"
    systemctl stop GhostRPC.service
    systemctl disable GhostRPC.service 2>/dev/null
    if [ -f "$SERVICE_FILE" ]; then
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
        echo -e "${YELLOW}Service file removed.${NC}"
    fi
    echo -e "${GREEN}Service Stopped.${NC}"
}

function restart_service() {
    if [ -f "$SERVICE_FILE" ]; then
        echo -e "${CYAN}Restarting GhostRPC...${NC}"
        systemctl restart GhostRPC.service
        echo -e "${GREEN}Service Restarted.${NC}"
    else
        echo -e "${RED}Service file not found. Please Start the service first to generate it.${NC}"
    fi
}

function update_app() {
    echo -e "${CYAN}Stopping service for update...${NC}"
    systemctl stop GhostRPC.service
    
    echo -e "${CYAN}Downloading latest version...${NC}"
    wget -qO /tmp/GhostRPC.tar.gz "$REPO_URL" || curl -sL -o /tmp/GhostRPC.tar.gz "$REPO_URL"
    
    if [ -f "/tmp/GhostRPC.tar.gz" ]; then
        echo -e "${CYAN}Extracting update...${NC}"
        mkdir -p /tmp/GhostRPC_update
        tar -xzvf /tmp/GhostRPC.tar.gz -C /tmp/GhostRPC_update --strip-components=1
        
        echo -e "${CYAN}Replacing binary and scripts...${NC}"
        cp /tmp/GhostRPC_update/GhostRPC $BIN_PATH
        chmod +x $BIN_PATH
        cp /tmp/GhostRPC_update/ghostrpc.sh /root/GhostRPC/ghostrpc.sh
        chmod +x /root/GhostRPC/ghostrpc.sh
        
        rm -rf /tmp/GhostRPC.tar.gz /tmp/GhostRPC_update
        
        if [ -f "$SERVICE_FILE" ]; then
            echo -e "${CYAN}Restarting service...${NC}"
            systemctl start GhostRPC.service
        fi
        echo -e "${GREEN}Update completed successfully!${NC}"
    else
        echo -e "${RED}Failed to download update.${NC}"
    fi
}

function uninstall_app() {
    read -p "Are you sure you want to completely uninstall GhostRPC? (y/N): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${CYAN}Stopping and removing service...${NC}"
        systemctl stop GhostRPC.service 2>/dev/null
        systemctl disable GhostRPC.service 2>/dev/null
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
        
        echo -e "${CYAN}Removing application directory...${NC}"
        rm -rf "$APP_DIR"
        
        echo -e "${CYAN}Removing symlink...${NC}"
        rm -f /usr/local/bin/ghostrpc
        
        echo -e "${GREEN}GhostRPC has been successfully uninstalled.${NC}"
        echo -e "${CYAN}You can reinstall the program with the following command:${NC}"
        echo -e "${GREEN}curl -sSL https://raw.githubusercontent.com/ArashAfkandeh/GhostRPC/main/install.sh | sudo bash${NC}"
        exit 0
    else
        echo -e "${YELLOW}Uninstall cancelled.${NC}"
    fi
}

function show_menu() {
    clear
    echo -e "${CYAN}=======================================${NC}"
    echo -e "         ${YELLOW}GhostRPC Manager${NC}            "
    echo -e "   Status: $(get_status)"
    echo -e "${CYAN}=======================================${NC}"
    echo "1) Start Service (Create if missing)"
    echo "2) Stop Service & Remove Unit"
    echo "3) Restart Service"
    echo "4) Update GhostRPC"
    echo "5) Uninstall GhostRPC"
    echo "0) Exit"
    echo -e "${CYAN}=======================================${NC}"
    read -p "Enter choice: " choice
    echo ""
    
    case $choice in
        1) start_service ;;
        2) stop_service ;;
        3) restart_service ;;
        4) update_app ;;
        5) uninstall_app ;;
        0) exit 0 ;;
        *) echo -e "${RED}Invalid choice!${NC}" ;;
    esac
    
    echo ""
    read -n 1 -s -r -p "Press any key to return to menu..."
    show_menu
}

show_menu
