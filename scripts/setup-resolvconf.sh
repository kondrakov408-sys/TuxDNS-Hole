#!/usr/bin/env bash
# ==============================================================================
# Setup and Lock /etc/resolv.conf for TuxDNS-Hole
# ==============================================================================
set -euo pipefail

echo "[+] Configuring system DNS for TuxDNS-Hole..."

# 1. Disable and stop systemd-resolved stub listener if active
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    echo "[*] Stopping and disabling systemd-resolved..."
    systemctl disable --now systemd-resolved || true
fi

# 2. Remove immutable flag if already set previously
if [ -f /etc/resolv.conf ]; then
    chattr -i /etc/resolv.conf 2>/dev/null || true
    rm -f /etc/resolv.conf
fi

# 3. Create clean local loopback resolv.conf (dual-stack)
echo "[*] Writing local nameserver entries to /etc/resolv.conf..."
cat << 'EOF' > /etc/resolv.conf
# Managed by TuxDNS-Hole (Zero-Log Local Sinkhole)
nameserver 127.0.0.1
nameserver ::1
options edns0 trust-ad
EOF

# 4. Make immutable so NetworkManager / DHCP client cannot overwrite it
if command -v chattr >/dev/null 2>&1; then
    echo "[*] Setting immutable attribute (+i) on /etc/resolv.conf..."
    chattr +i /etc/resolv.conf
    echo "[✓] /etc/resolv.conf is now locked against external overrides."
fi

echo "[✓] Setup complete. Test resolution via: dig example.com @127.0.0.1"
