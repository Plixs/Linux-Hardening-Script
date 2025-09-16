#!/bin/bash
set -e

# -----------------------
# 系统检测和更新
# -----------------------
detect_update_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        echo "Unsupported OS. Exiting."
        exit 1
    fi

    echo "[+] Updating system packages..."
    if [[ "$OS" =~ (debian|ubuntu) ]]; then
        apt update && apt upgrade -y
    elif [[ "$OS" =~ (centos|almalinux|rhel) ]]; then
        dnf update -y
    else
        echo "Unsupported OS for update. Skipping..."
    fi
}

# -----------------------
# SELinux 调整（RedHat 系列可选）
# -----------------------
adjust_selinux() {
    if [[ -f /etc/selinux/config ]]; then
        echo "[+] Adjusting SELinux to permissive (if needed)..."
        sed -i 's/^SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
        setenforce 0 || true
    fi
}

# -----------------------
# SSH 用户配置（密码或公钥）
# -----------------------
setup_user_ssh() {
    local USERNAME="$1"
    local LOGIN_METHOD="$2"

    case "$LOGIN_METHOD" in
        password)
            passwd "$USERNAME"
            ;;
        key)
            echo "[+] Paste SSH public key for $USERNAME:"
            read -r PUBKEY
            if [[ "$PUBKEY" =~ ^ssh-(rsa|ed25519|ecdsa|dss) ]]; then
                mkdir -p /home/$USERNAME/.ssh
                echo "$PUBKEY" >> /home/$USERNAME/.ssh/authorized_keys
                chmod 700 /home/$USERNAME/.ssh
                chmod 600 /home/$USERNAME/.ssh/authorized_keys
                chown -R $USERNAME:$USERNAME /home/$USERNAME/.ssh
            else
                echo "Invalid SSH key. Skipping."
            fi
            ;;
        skip)
            echo "[+] Skipping SSH key/password setup for $USERNAME"
            ;;
        *)
            echo "[!] Unknown login method: $LOGIN_METHOD"
            ;;
    esac
}

# -----------------------
# 可选新 sudo 用户创建
# -----------------------
optional_new_sudo_user_setup() {
    local NEW_USER="$1"
    local LOGIN_METHOD="$2"

    if id "$NEW_USER" >/dev/null 2>&1; then
        echo "[+] User $NEW_USER already exists."
    else
        useradd -m -s /bin/bash "$NEW_USER"
        usermod -aG sudo "$NEW_USER"
        setup_user_ssh "$NEW_USER" "$LOGIN_METHOD"
    fi
}

# -----------------------
# 可选 root 登录管理
# -----------------------
optional_root_login_manage() {
    local ROOT_METHOD="$1"
    setup_user_ssh "root" "$ROOT_METHOD"
}

# -----------------------
# SSH 端口修改
# -----------------------
change_ssh_port() {
    while true; do
        read -rp "Enter a new SSH port (1-65535) [Random high port]: " SSH_PORT
        if [[ -z "$SSH_PORT" ]]; then
            SSH_PORT=$(( (RANDOM % 55535) + 10000 ))
        fi
        if [[ "$SSH_PORT" =~ ^[0-9]+$ && $SSH_PORT -ge 1 && $SSH_PORT -le 65535 ]]; then
            break
        fi
        echo "Invalid port. Please enter a number between 1 and 65535."
    done

    sed -i "s/^#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
    systemctl restart sshd
    echo "[+] SSH port changed to $SSH_PORT"
}

# -----------------------
# Fail2Ban 安装及配置
# -----------------------
setup_fail2ban() {
    echo "[+] Installing Fail2Ban..."
    if [[ "$OS" =~ (debian|ubuntu) ]]; then
        apt install fail2ban -y
    elif [[ "$OS" =~ (centos|almalinux|rhel) ]]; then
        dnf install fail2ban -y
    fi

    cat >/etc/fail2ban/jail.local <<EOF
[sshd]
enabled  = true
port     = ssh
logpath  = /var/log/auth.log
maxretry = 5
findtime = 600
bantime  = 3600
backend  = systemd
mode     = aggressive
EOF

    systemctl enable --now fail2ban
}

# -----------------------
# 防火墙可选配置
# -----------------------
setup_firewall() {
    if command -v ufw >/dev/null 2>&1; then
        ufw allow "$SSH_PORT"/tcp
        ufw enable
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="$SSH_PORT"/tcp
        firewall-cmd --reload
    fi
}

# -----------------------
# Lynis 安装与审计
# -----------------------
setup_lynis() {
    if [[ "$OS" =~ (debian|ubuntu) ]]; then
        apt install lynis -y
    elif [[ "$OS" =~ (centos|almalinux|rhel) ]]; then
        dnf install lynis -y
    fi

    echo "[+] Starting initial Lynis audit..."
    lynis audit system --quick
}

# -----------------------
# 系统日志与缓存清理
# -----------------------
cleanup_system() {
    echo "[+] Cleaning up logs and cache to free space..."
    # Journalctl 按时间和大小
    if command -v journalctl >/dev/null 2>&1; then
        journalctl --vacuum-time=7d || true
        journalctl --vacuum-size=100M || true
    fi
    # /var/log 日志
    find /var/log -type f -name "*.log" -mtime +7 -exec truncate -s 0 {} \;
    find /var/log -type f -name "*.log" -size +10M -exec truncate -s 0 {} \;
    find /var/log -type f -name "*.gz" -delete || true
    # 清理包缓存
    if [[ "$OS" =~ (debian|ubuntu) ]]; then
        apt clean
    elif [[ "$OS" =~ (centos|almalinux|rhel) ]]; then
        dnf clean all
    fi
    # 清理临时目录
    rm -rf /tmp/* /var/tmp/* || true
    echo "[+] Cleanup done."
}

# -----------------------
# Main
# -----------------------
main() {
    detect_update_os

    # adjust_selinux

    # Root 登录选项
    read -rp "Do you want to disable root login? (y/N): " disable_root
    if [[ "$disable_root" =~ ^[Yy]$ ]]; then
        ROOT_LOGIN_METHOD="skip"
        read -rp "Enter new sudo username: " NEW_SUDO_USER
        read -rp "Choose login method for new sudo user (password/key/skip): " user_method
        optional_new_sudo_user_setup "$NEW_SUDO_USER" "$user_method"
        read -rp "Do you want to change root password? (y/N): " change_root_pw
        if [[ "$change_root_pw" =~ ^[Yy]$ ]]; then
            passwd root
        fi
    else
        read -rp "Choose root login method (password/key/skip): " ROOT_LOGIN_METHOD
        optional_root_login_manage "$ROOT_LOGIN_METHOD"
        read -rp "Do you want to change root password? (y/N): " change_root_pw
        if [[ "$change_root_pw" =~ ^[Yy]$ ]]; then
            passwd root
        fi
        read -rp "Do you want to create a new sudo user? (y/N): " create_sudo
        if [[ "$create_sudo" =~ ^[Yy]$ ]]; then
            read -rp "Enter new sudo username: " NEW_SUDO_USER
            read -rp "Choose login method for new sudo user (password/key/skip): " user_method
            optional_new_sudo_user_setup "$NEW_SUDO_USER" "$user_method"
        fi
    fi

    # SSH port change
    change_ssh_port

    # Fail2Ban
    setup_fail2ban

    # Firewall (optional)
    read -rp "Do you want to configure firewall? (y/N): " setup_fw
    if [[ "$setup_fw" =~ ^[Yy]$ ]]; then
        setup_firewall
    fi

    # Lynis optional
    read -rp "Do you want to install and run Lynis audit? (y/N): " lynis_choice
    if [[ "$lynis_choice" =~ ^[Yy]$ ]]; then
        setup_lynis
    fi

    # Cleanup system
    cleanup_system
}

main
