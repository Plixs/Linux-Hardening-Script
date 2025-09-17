# Linux Hardening Script

A one-click script to update and harden your Linux VPS or server. Supports:

- Ubuntu
- Debian
- CentOS
- AlmaLinux

## Features

- System updates
- SSH port change (with prompt)
- Fail2Ban & Lynis installation
- Optional root login disablement
- Optional new sudo user setup
- Firewall configuration
- SELinux handling
- Quick audit with Lynis

**By [Hosteons.com](https://hosteons.com)**

> ⚠️ Use with caution. Ensure VNC or IPMI access before changing SSH settings.

Modfiy By AI,NOT FULL TEST.

```bash
wget -N -O harden.sh https://github.com/Plixs/Linux-Hardening-Script/raw/refs/heads/main/harden.sh && bash harden.sh
```

or

```bash
bash <(curl -fsSL https://github.com/Plixs/Linux-Hardening-Script/raw/refs/heads/main/harden.sh)
```
