#!/bin/bash
set -euo pipefail

# -----------------------
# 工具函数
# -----------------------

is_container() {
    # LXD / systemd-nspawn / OpenVZ / Docker
    [[ -f /run/.containerenv ]] \
    || [[ -d /run/systemd/system ]] && grep -qa 'container=' /run/systemd/system/* 2>/dev/null \
    || grep -qaE 'lxc|lxd|container' /proc/1/environ 2>/dev/null \
    || [[ -f /proc/user_beancounters ]]   # OpenVZ
}

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
            # 禁用密码登录（只允许 SSH key）
            sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
            # 确保公钥认证开启
            sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
            
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

    # 1. 安装
    if [[ "$OS" =~ (debian|ubuntu) ]]; then
        apt install -y fail2ban
    elif [[ "$OS" =~ (centos|almalinux|rhel) ]]; then
        dnf install -y fail2ban
    fi

        # 2. 拷贝默认配置为 .local（仅首次）
    [[ -f /etc/fail2ban/fail2ban.conf && ! -f /etc/fail2ban/fail2ban.local ]] \
        && sudo cp /etc/fail2ban/fail2ban.conf /etc/fail2ban/fail2ban.local

    [[ -f /etc/fail2ban/jail.conf && ! -f /etc/fail2ban/jail.local ]] \
        && sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

    # 3. 确保日志文件目录存在（有些轻量系统没有 /var/log/auth.log）
    if [[ ! -f /var/log/auth.log ]]; then
        sudo mkdir -p /var/log
        sudo touch /var/log/auth.log
        sudo chmod 640 /var/log/auth.log
        sudo chown root:adm /var/log/auth.log 2>/dev/null || true
    fi

    # 4. 写入 sshd jail 配置（追加或覆盖）
    sudo tee /etc/fail2ban/jail.d/sshd.local >/dev/null <<'EOF'
    [sshd]
    enabled  = true
    port     = ssh
    logpath  = /var/log/auth.log
    backend  = systemd
    maxretry = 5
    findtime = 600
    bantime  = 3600
    mode     = aggressive
EOF

    # 5. 启动并开机自启
    sudo systemctl enable --now fail2ban
    sudo systemctl restart fail2ban

    echo "[OK] Fail2ban has been installed and configured."
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
    # T
    echo "[+] Logrotate configured."
}

ensure_sshd_run_dir() {
    if is_container; then
        echo "[*] 1/5 写入 tmpfiles 规则..."
        cat <<'EOF' > /etc/tmpfiles.d/sshd.conf
        # 确保 /run/sshd 每次开机都自动创建
        d /run/sshd 0755 root root -
EOF
        
        echo "[*] 2/5 立即创建目录并设置权限..."
        mkdir -p /run/sshd
        chmod 755 /run/sshd
        
        echo "[*] 3/5 配置 sshd ExecStartPre..."
        mkdir -p /etc/systemd/system/ssh.service.d
        cat <<'EOF' > /etc/systemd/system/ssh.service.d/create-run-sshd.conf
        [Service]
        ExecStartPre=/bin/mkdir -p /run/sshd
        ExecStartPre=/bin/chmod 755 /run/sshd
EOF
        
        echo "[*] 4/5 重新加载 systemd 与 tmpfiles..."
        systemd-tmpfiles --create
    
    fi
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
    # adjust_selinux
    
    # ensure_sshd_run_dir
    ensure_sshd_run_dir
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
    echo "[*] Setting SSH port to $SSHPORT..."
    sed -i "s/^#Port .*/Port $SSHPORT/" /etc/ssh/sshd_config || echo "Port $SSHPORT" >> /etc/ssh/sshd_config

    # Root login optional
    read -rp "Do you want to disable root login? (y/N): " disable_root
    read -rp "Enter new sudo username: " sudo_user_name

    if [[ "$disable_root" =~ ^[Yy]$ ]]; then
        setup_sudo_user "$sudo_user_name"
        echo "[*] Disabling root login via SSH..."
        sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
       
        echo "Before read root password"
        read -rp "Do you want to change root password? (y/N): " choice;
        echo "After read, choice='$choice'"
        [[ "$choice" =~ ^[Yy]$ ]] && passwd root
    else
        read -rp "Root login method (password/key/skip) [skip]: " root_login_method
        root_login_method=${root_login_method:-skip}
        setup_sudo_user "$sudo_user_name"
        modify_root_login "$root_login_method"
    fi

    sudo systemctl reload sshd
 
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
