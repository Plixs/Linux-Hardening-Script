#!/bin/bash

# Linux Hardening Script by Hosteons.com
# License: MIT

echo "--------------------------------------------------"
echo "       Linux Update and Hardening Script"
echo "            By https://hosteons.com"
echo "--------------------------------------------------"

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Unsupported OS. Exiting."
    exit 1
fi

# Update system
echo "[+] Updating system packages..."
if [[ "$OS" =~ (debian|ubuntu) ]]; then
    apt update && apt upgrade -y
elif [[ "$OS" =~ (centos|almalinux|rhel) ]]; then
    dnf update -y
else
    echo "Unsupported OS for update. Skipping..."
fi

# Install hardening tools
echo "[+] Installing Fail2Ban and Lynis..."
if [[ "$OS" =~ (debian|ubuntu) ]]; then
    apt install -y fail2ban lynis
    systemctl enable --now fail2ban
elif [[ "$OS" =~ (centos|almalinux|rhel) ]]; then
    dnf install -y epel-release
    dnf install -y fail2ban lynis
    systemctl enable --now fail2ban
fi

# SSH port change
while true; do
    read -rp "Enter a new SSH port (e.g. 2222): " SSHPORT
    if [[ "$SSHPORT" =~ ^[0-9]+$ && $SSHPORT -ge 1 && $SSHPORT -le 65535 ]]; then
        break
    fi
    echo "Invalid port. Please enter a number between 1 and 65535."
done

echo "[+] Updating SSH port to $SSHPORT..."
sed -i "s/^#Port .*/Port $SSHPORT/" /etc/ssh/sshd_config
sed -i "s/^Port .*/Port $SSHPORT/" /etc/ssh/sshd_config

# SELinux adjustment
if [[ -f /etc/selinux/config ]]; then
    echo "[+] Adjusting SELinux to permissive (if needed)..."
    sed -i 's/^SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
    setenforce 0 || true
fi

# Firewall rules
echo "[+] Adjusting firewall rules..."
if command -v ufw &>/dev/null; then
    ufw allow $SSHPORT
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-port=${SSHPORT}/tcp
    firewall-cmd --reload
fi

# Disable root login
read -rp "Do you want to disable SSH root login? (y/n): " DISABLE_ROOT
if [[ "$DISABLE_ROOT" =~ ^[Yy]$ ]]; then
    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

    read -rp "Enter new sudo username: " NEWUSER
    adduser $NEWUSER
    passwd $NEWUSER
    usermod -aG sudo $NEWUSER

    echo "Root login disabled. Use the following to switch to root:"
    echo "  su -"
    echo "Or use sudo with your new user: sudo <command>"
fi

# Restart SSH
echo "[+] Restarting SSH service..."
systemctl restart ssh || systemctl restart sshd

# Run Lynis audit
echo "[+] Starting initial Lynis audit..."
lynis audit system --quick

echo "[✔] Hardening completed. Don't forget to test SSH access before closing current session."
echo "For more scripts visit https://github.com/hosteons"

