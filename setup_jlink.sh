#!/bin/bash

JLINK_VERSION="V812g"
JLINK_DIR="JLink_Linux_${JLINK_VERSION}_arm"
JLINK_TGZ="JLink_Linux_arm.tgz"
JLINK_DOWNLOAD_URL="https://www.segger.com/downloads/jlink/JLink_Linux_arm.tgz"
JLINK_EXEC="$HOME/$JLINK_DIR/JLinkRemoteServerCLExe"
JLINK_SERVICE_FILE="/etc/systemd/system/jlink-remote-server.service"

echo "Starting J-Link setup for Raspberry Pi..."

if [[ ! -f "$JLINK_TGZ" ]]; then
    echo "Downloading J-Link utilities..."
    wget --post-data 'accept_license_agreement=accepted&non_emb_ctr=confirmed&submit=Download+software' "$JLINK_DOWNLOAD_URL" -O "$JLINK_TGZ"

else
    echo "J-Link archive already exists. Skipping download."
fi

echo "Extracting J-Link archive..."
tar xvf "$JLINK_TGZ"

echo "Installing udev rules..."
sudo cp "$JLINK_DIR/99-jlink.rules" /etc/udev/rules.d/

IS_PI_ZERO=$(cat /proc/cpuinfo | grep "Hardware" | grep -q "BCM2835" && echo "yes" || echo "no")

if [[ "$IS_PI_ZERO" == "no" ]]; then
    echo "Configuring rc.local to start J-Link Remote Server on boot..."
    sudo sed -i '/exit 0/i \
    '"$JLINK_EXEC -Port 19020 &" /etc/rc.local
    echo "Rebooting to apply changes..."
    sudo reboot
else
    echo "Setting up systemd service for J-Link Remote Server..."
    
    sudo bash -c "cat > $JLINK_SERVICE_FILE" <<EOF
[Unit]
Description=JLink Remote Server
After=network.target

[Service]
Type=simple
ExecStart=$JLINK_EXEC -Port 19020
WorkingDirectory=$HOME
User=pi
Group=pi
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    echo "Enabling and starting the systemd service..."
    sudo systemctl daemon-reload
    sudo systemctl enable jlink-remote-server.service
    sudo systemctl start jlink-remote-server.service
    echo "Systemd service setup complete. Rebooting..."
    sudo reboot
fi
