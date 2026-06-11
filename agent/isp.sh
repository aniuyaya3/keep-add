#!/bin/sh
echo "=========================================================="
echo "     卸载 Proxy Controller (主备双活引擎)          "
echo "=========================================================="

# 检测系统类型
if command -v apk >/dev/null 2>&1; then
    SYS_TYPE="ALPINE"
else
    SYS_TYPE="DEBIAN"
fi

echo "[*] 停止服务..."
if [ "$SYS_TYPE" = "ALPINE" ]; then
    rc-service proxy-lite stop 2>/dev/null
    rc-update del proxy-lite default 2>/dev/null
elif [ "$SYS_TYPE" = "DEBIAN" ]; then
    systemctl stop proxy-lite.service 2>/dev/null
    systemctl disable proxy-lite.service 2>/dev/null
    rm -f /lib/systemd/system/proxy-lite.service
    systemctl daemon-reload
fi

echo "[*] 杀掉残留进程..."
pkill -f "openvpn.*tun_main|tun_backup" 2>/dev/null || true
pkill -f "lite_manager|proxy_server" 2>/dev/null || true

echo "[*] 清理路由和 iptables 规则..."
iptables -F
iptables -t nat -F
iptables -t mangle -F
ip rule del pref 101 2>/dev/null || true
ip rule del pref 1101 2>/dev/null || true
ip rule del pref 102 2>/dev/null || true
ip rule del pref 1102 2>/dev/null || true
ip route flush table 101 2>/dev/null || true
ip route flush table 102 2>/dev/null || true

echo "[*] 移除系统配置文件..."
rm -f /etc/sysctl.d/99-proxy-lite.conf
sysctl --system >/dev/null 2>&1

echo "[*] 删除程序文件..."
rm -rf /opt/proxy_lite
rm -f /etc/init.d/proxy-lite  # Alpine
rm -f /lib/systemd/system/proxy-lite.service  # Debian/Ubuntu

echo "[+] Proxy Controller 卸载完成！系统已恢复干净。"
