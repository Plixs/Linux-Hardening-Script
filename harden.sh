#!/bin/bash
set -e

# -----------------------
# 配置参数
# -----------------------
SSH_PORT_DEFAULT=0
NEW_SUDO_USER=""        # 传入可选参数
ROOT_LOGIN_METHOD=""    # password/key/skip
LYNIS_OPTIONAL=false

# -----------------------
# 函数定义
# -----------------------

adjust_selinux() {
    if [[ -f /etc/selinux/config ]]; then
        echo "[+] Adjusting SELinux to permissive (if needed)..."
        sed -i 's/^SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
        setenforce 0 || true
    fi
}

setup_user_ssh() {
    local username="$1"
    local method="$2"

    if [[ "$method" == "key" ]]; then
        while true; do
            read -rp "Paste the public SSH key for $username: " pubkey
            if [[ "$pubkey" =~ ^ssh-(rsa|ed25519|ecdsa|dss) ]]; then
                mkdir -p /home/$username/.ssh
                echo "$pubkey" > /home/$username/.ssh/authorized_keys
                chmod 700 /home/$username/.ssh
                chmod 600 /home/$username/.ssh/authorized_keys
                chown -R $username:$username /home/$username/.ssh
                echo "[+] SSH key added for $username"
                break
            fi
            echo "Invalid SSH key. Please try again."
        done
    elif [[ "$method" == "password" ]]; then
        passwd $username
    else
        echo "[*] Skipping SSH setup for $username"
    fi
}

optional_new_sudo_user_setup() {
    local new_user="$1"
    local root_method="$2"

    if [[ "$new_user" == "true" ]]; then
        read -rp "Enter new sudo username: " sudo_user
        adduser $sudo_user
        usermod -aG sudo $sudo_user
        setup_user_ssh "$sudo_user" "$root_method"
    fi
}

optional_root_login_disable() {
    local method="$1"

    echo "[*] Configuring root login method..."
    case "$method" in
        key)
            setup_user_ssh "root" "key"
            ;;
        password)
            passwd root
            ;;
        skip)
            echo "[*] Skipping root password/key change"
            ;;
    esac
}

change_ssh_port() {
    while true; do
        read -rp "Enter a new SSH port (1-65535), or press Enter to use a random high port: " SSH_PORT
        if [[ -z "$SSH_PORT" ]]; then
            SSH_PORT=$((RANDOM % 64512 + 1024))
            break
        elif [[ "$SSH_PORT" =~ ^[0-9]+$ ]] && [ "$SSH_PORT" -ge 1 ] && [ "$SSH_PORT" -le 65535 ]; then
            break
        fi
        echo "Invalid port. Enter a number between 1 and 65535."
    done
    sed -i "s/^#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
    systemctl restart ssh
    echo "[+] SSH port changed to $SSH_PORT"
}

install_fail2ban() {
    apt update
    apt install -y fail2ban
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
}

install_lynis() {
    local use_lynis="$1"
    if [[ "$use_lynis" == "true" ]]; then
        apt install -y lynis
        echo "[+] Starting initial Lynis audit..."
        lynis audit system --quick
    fi
}

# -----------------------
# 主逻辑
# -----------------------
main() {
    echo "[*] Linux hardening script starting..."

    # adjust_selinux
    # optional, only for RedHat systems

    echo "[*] SSH Port Configuration"
    change_ssh_port

    echo "[*] Root login configuration"
    read -rp "Choose root login method (password/key/skip): " ROOT_LOGIN_METHOD
    optional_root_login_disable "$ROOT_LOGIN_METHOD"

    echo "[*] Sudo user setup"
    NEW_SUDO_USER="true"
    optional_new_sudo_user_setup "$NEW_SUDO_USER" "$ROOT_LOGIN_METHOD"

    echo "[*] Installing Fail2ban..."
    install_fail2ban

    read -rp "Do you want to install Lynis? (y/N): " lynis_choice
    if [[ "$lynis_choice" =~ ^[Yy]$ ]]; then
        LYNIS_OPTIONAL=true
    fi
    install_lynis "$LYNIS_OPTIONAL"

    echo "[+] Hardening script completed."
}

main
