#!/bin/bash
set -e

# -----------------------
# 工具函数
# -----------------------
setup_user_ssh() {
    local user=$1
    while true; do
        read -rp "Paste SSH public key for $user (leave empty to skip): " pubkey
        if [[ -z "$pubkey" ]]; then
            echo "[*] Skipping SSH key setup for $user."
            break
        elif [[ "$pubkey" =~ ^ssh-(rsa|ed25519|dsa|ecdsa) ]]; then
            mkdir -p /home/$user/.ssh
            echo "$pubkey" > /home/$user/.ssh/authorized_keys
            chmod 600 /home/$user/.ssh/authorized_keys
            chown -R $user:$user /home/$user/.ssh
            echo "[+] SSH key added for $user."
            break
        else
            echo "Invalid SSH key format. Try again."
        fi
    done
}

setup_sudo_user() {
    local user=$1
    echo "[*] Creating sudo user: $user"

    while true; do
        read -rsp "Set password for $user: " passwd
        echo
        read -rsp "Confirm password: " passwd2
        echo
        if [[ "$passwd" == "$passwd2" && -n "$passwd" ]]; then
            break
        else
            echo "Passwords do not match or empty. Try again."
        fi
    done

    useradd -m -s /bin/bash "$user"
    echo "$user:$passwd" | chpasswd
    usermod -aG sudo "$user"
    echo "[+] Sudo user $user created with password."
    setup_user_ssh "$user"
}

modify_root_login() {
    local root_method=$1

    case "$root_method" in
        password)
            echo "[*] Root login: keep existing password."
            ;;
        key)
            setup_user_ssh "root"
            ;;
        skip)
            echo "[*] Skipping root SSH key setup."
            ;;
        *)
            echo "[!] Unknown root login method, skipping."
            ;;
    esac

    read -rp "Do you want to change root password? (y/N): " choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        passwd root
    fi
}

adjust_selinux() {
    # adjust_selinux
    if [[ -f /etc/selinux/config ]]; then
        echo "[+] Adjusting SELinux to permissive (if needed)..."
        sed -i 's/^SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
        setenforce 0 || true
    fi
}

install_fail2ban() {
    echo "[+] Installing fail2ban..."
    if [[ "$OS" =~ (debian|ubuntu) ]]; then
        apt install -y fail2ban
    elif [[ "$OS" =~ (centos|almalinux|rhel) ]]; then
        dnf install -y fail2ban
    fi

    cat >/etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 5
findtime = 600
bantime = 3600
backend = systemd
mode = aggressive
EOF

    systemctl enable --now fail2ban
    echo "[+] fail2ban configured."
}

install_lynis() {
    echo "[+] Installing Lynis..."
    if [[ "$OS" =~ (debian|ubuntu) ]]; then
        apt install -y lynis
    elif [[ "$OS" =~ (centos|almalinux|rhel) ]]; then
        dnf install -y lynis
    fi
    echo "[+] Starting initial Lynis audit..."
    lynis audit system --quick
}

configure_firewall() {
    read -rp "Do you want to configure firewall? (y/N): " choice
    if [[ ! "$choice" =~ ^[Yy]$ ]]; then
        echo "[*] Skipping firewall configuration."
        return
    fi

    echo "[*] Configuring firewall..."
    if command -v ufw >/dev/null 2>&1; then
        ufw allow "$SSH_PORT"
        ufw enable
        echo "[+] UFW enabled and SSH port allowed."
    elif command -v firewall-cmd >/dev/null 2>&1; then
        systemctl enable --now firewalld
        firewall-cmd --permanent --add-port="$SSH_PORT"/tcp
        firewall-cmd --reload
        echo "[+] firewalld enabled and SSH port allowed."
    else
        echo "[*] No supported firewall detected, skipping."
    fi
}

setup_logrotate() {
    echo "[*] Configuring logrotate for auth and system logs..."
    cat >/etc/logrotate.d/custom_logs <<EOF
/var/log/auth.log
/var/log/syslog
{
    daily
    rotate 7
    size 50M
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF
    echo "[+] Logrotate configured."
}

# -----------------------
# 主逻辑
# -----------------------
main() {
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

    # adjust_selinux
    adjust_selinux

    # SSH port
    while true; do
        read -rp "Enter new SSH port (1-65535, leave empty for random high port): " SSH_PORT
        if [[ -z "$SSH_PORT" ]]; then
            SSH_PORT=$((RANDOM % 64512 + 1024))
            echo "[*] Random SSH port selected: $SSH_PORT"
            break
        elif [[ "$SSH_PORT" =~ ^[0-9]+$ && $SSH_PORT -ge 1 && $SSH_PORT -le 65535 ]]; then
            break
        else
            echo "Invalid port. Enter number 1-65535."
        fi
    done

    # Root login optional
    read -rp "Do you want to disable root login? (y/N): " disable_root
    read -rp "Enter new sudo username: " sudo_user_name

    if [[ "$disable_root" =~ ^[Yy]$ ]]; then
        setup_sudo_user "$sudo_user_name"
        echo "[*] Disabling root login via SSH..."
        sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
        systemctl restart sshd
        read -rp "Do you want to change root password? (y/N): " choice
        [[ "$choice" =~ ^[Yy]$ ]] && passwd root
    else
        read -rp "Root login method (password/key/skip) [skip]: " root_login_method
        root_login_method=${root_login_method:-skip}
        setup_sudo_user "$sudo_user_name"
        modify_root_login "$root_login_method"
    fi

    # Fail2ban
    install_fail2ban

    # Lynis
    read -rp "Do you want to install Lynis and run initial audit? (y/N): " choice
    [[ "$choice" =~ ^[Yy]$ ]] && install_lynis

    # Optional firewall
    configure_firewall

    # Logrotate
    setup_logrotate

    echo "[+] Hardening script completed!"
}

main
