#!/bin/bash
set -e

# -----------------------
# Helper functions
# -----------------------

adjust_selinux() {
    if [[ -f /etc/selinux/config ]]; then
        echo "[+] Adjusting SELinux to permissive mode..."
        sed -i 's/^SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
        setenforce 0 2>/dev/null || true
        echo "[+] SELinux adjustment completed."
        return 0
    else
        echo "[*] SELinux config not found, skipping adjustment."
        return 1
    fi
}

generate_random_port() {
    shuf -i 1024-65535 -n 1
}

setup_user_ssh() {
    local username="$1"
    local method="$2"  # "password" or "key"
    if [[ "$method" == "key" ]]; then
        while true; do
            read -rp "Paste the public SSH key for $username: " pubkey
            if [[ "$pubkey" =~ ^ssh-(rsa|ed25519|dss|ecdsa) ]]; then
                mkdir -p /home/$username/.ssh
                echo "$pubkey" > /home/$username/.ssh/authorized_keys
                chmod 700 /home/$username/.ssh
                chmod 600 /home/$username/.ssh/authorized_keys
                chown -R $username:$username /home/$username/.ssh
                echo "[+] SSH key added for $username"
                break
            else
                echo "Invalid SSH key format. Try again."
            fi
        done
    elif [[ "$method" == "password" ]]; then
        passwd "$username"
    fi
}

optional_new_sudo_user_setup() {
    local new_user="$1"
    local login_method="$2"
    if [[ "$new_user" == "true" ]]; then
        read -rp "Enter new sudo username: " sudo_user
        useradd -m -s /bin/bash "$sudo_user"
        usermod -aG sudo "$sudo_user"
        setup_user_ssh "$sudo_user" "$login_method"
    fi
}

optional_root_login_disable() {
    local method="$1"  # password/key/skip
    if [[ "$method" == "key" ]]; then
        setup_user_ssh "root" "key"
        sed -i 's/^PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    elif [[ "$method" == "password" ]]; then
        passwd root
        sed -i 's/^PermitRootLogin yes/PermitRootLogin yes/' /etc/ssh/sshd_config
    elif [[ "$method" == "skip" ]]; then
        echo "[*] Skipping root login changes."
    fi
}

configure_ssh_port() {
    local port
    while true; do
        read -rp "Enter a new SSH port (or leave empty for random): " port
        if [[ -z "$port" ]]; then
            port=$(generate_random_port)
            echo "[*] Using random port $port"
            break
        elif [[ "$port" =~ ^[0-9]+$ && $port -ge 1 && $port -le 65535 ]]; then
            break
        else
            echo "Invalid port. Enter 1-65535."
        fi
    done
    sed -i "s/^#Port 22/Port $port/" /etc/ssh/sshd_config
    systemctl restart ssh
    echo "[+] SSH port configured to $port"
}

install_fail2ban() {
    apt install -y fail2ban
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

install_lynis() {
    local use_lynis="$1"
    if [[ "$use_lynis" == "true" ]]; then
        apt install -y lynis
    fi
}

# -----------------------
# Main
# -----------------------
main() {
    echo "[*] Starting system hardening..."

    # Detect OS and update
    echo "[*] Updating system packages..."
    apt update -y && apt upgrade -y

    # Adjust SELinux
    # adjust_selinux

    # Optional root login changes
    echo "Choose root login method: password/key/skip"
    read -r ROOT_LOGIN_METHOD
    optional_root_login_disable "$ROOT_LOGIN_METHOD"

    # Optional new sudo user
    echo "Do you want to create a new sudo user? (y/N)"
    read -r choice
    NEW_SUDO_USER=false
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        NEW_SUDO_USER=true
        echo "Choose login method for new sudo user: password/key"
        read -r login_method
        optional_new_sudo_user_setup "$NEW_SUDO_USER" "$login_method"
    fi

    # SSH port configuration
    configure_ssh_port

    # Install fail2ban
    install_fail2ban

    # Install Lynis optionally
    echo "Do you want to install Lynis? (y/N)"
    read -r lynis_choice
    LYNIS_OPTIONAL=false
    if [[ "$lynis_choice" =~ ^[Yy]$ ]]; then
        LYNIS_OPTIONAL=true
    fi
    install_lynis "$LYNIS_OPTIONAL"

    echo "[+] System hardening completed!"
}

main "$@"
