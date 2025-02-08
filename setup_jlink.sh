#!/bin/bash

JLINK_VERSION="V646g"
USER="aruw"
JLINK_DIR="JLink_Linux_${JLINK_VERSION}_arm"
JLINK_TGZ="JLink_Linux_arm.tgz"
JLINK_DOWNLOAD_URL="https://www.segger.com/downloads/jlink/JLink_Linux_${JLINK_VERSION}_arm.tgz"
JLINK_EXEC="/home/$USER/$JLINK_DIR/JLinkRemoteServerCLExe"
JLINK_SERVICE_FILE="/etc/systemd/system/jlink-remote-server.service"

echo "Starting J-Link setup for Raspberry Pi..."

if [ ! -f /lib/ld-linux-armhf.so.3 ]; then
    echo "32-bit dynamic linker /lib/ld-linux-armhf.so.3 not found."
    echo "Enabling armhf architecture and installing required 32-bit libraries..."
    sudo dpkg --add-architecture armhf
    sudo apt update
    sudo apt install -y libc6:armhf
    echo "Creating symlink for 32-bit dynamic linker..."
    sudo ln -s /lib/arm-linux-gnueabihf/ld-linux-armhf.so.3 /lib/ld-linux-armhf.so.3
fi

echo "Downloading J-Link utilities..."
wget --post-data 'accept_license_agreement=accepted&non_emb_ctr=confirmed&submit=Download+software' "$JLINK_DOWNLOAD_URL" -O "$JLINK_TGZ"

echo "Extracting J-Link archive..."
tar xvf "$JLINK_TGZ"
cd "$JLINK_DIR"
echo "Installing udev rules..."
sudo cp 99-jlink.rules /etc/udev/rules.d/
sudo udevadm control -R
sudo udevadm trigger --action=remove --attr-match=idVendor=1366 --subsystem-match=usb
sudo udevadm trigger --action=add    --attr-match=idVendor=1366 --subsystem-match=usb

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
WorkingDirectory=/home/$USER/
User=$USER
Group=$USER
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
