#!/bin/bash

USER="aruw"
RTT_MANAGER_SCRIPT="/home/$USER/rtt_manager.py"
RTT_MANAGER_SERVICE_FILE="/etc/systemd/system/rtt-manager.service"

echo "Setting up RTT Manager service..."

if [ ! -f "$RTT_MANAGER_SCRIPT" ]; then
    echo "ERROR: $RTT_MANAGER_SCRIPT not found"
    exit 1
fi

chmod +x "$RTT_MANAGER_SCRIPT"

echo "Creating service file..."
sudo bash -c "cat > $RTT_MANAGER_SERVICE_FILE" <<'EOF'
[Unit]
Description=J-Link RTT Manager
After=network.target jlink-remote-server.service
Requires=jlink-remote-server.service
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/bin/python3 /home/aruw/rtt_manager.py
WorkingDirectory=/home/aruw
User=aruw
Group=aruw
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

Environment="RUN_AS_USER=aruw"
Environment="JLINK_DIR=/home/aruw/JLink_Linux_V812g_arm"
Environment="JLINK_DEVICE=STM32F427II"
Environment="JLINK_IFACE=SWD"
Environment="JLINK_SPEED_KHZ=4000"
Environment="JLINK_RS_HOST=127.0.0.1"
Environment="JLINK_RS_PORT=19020"
Environment="JLINK_RTT_PORT=19051"
Environment="JLINK_RTT_STREAM_ENABLED=1"
Environment="JLINK_RTT_STREAM_PORT=19052"
Environment="RS_SERVICE=jlink-remote-server.service"
Environment="START_RTT_CLIENT=1"
Environment="SELF_ATTACH_GRACE_S=3.0"
Environment="WAITING_DEBOUNCE_S=1.0"
Environment="JLINK_RTT_LOG_DIR=/home/aruw/jlink-rtt"

[Install]
WantedBy=multi-user.target
EOF

echo "Service file created: $RTT_MANAGER_SERVICE_FILE"

sudo systemctl daemon-reload
sudo systemctl enable rtt-manager.service

echo ""
echo "Setup complete"
echo ""
echo "Commands:"
echo "  Start:   sudo systemctl start rtt-manager.service"
echo "  Stop:    sudo systemctl stop rtt-manager.service"
echo "  Status:  sudo systemctl status rtt-manager.service"
echo "  Logs:    sudo journalctl -u rtt-manager.service -f"
echo ""
