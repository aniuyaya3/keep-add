cat > /tmp/uninstall_proxy_controller.sh <<'EOF'
#!/bin/sh
set +e

echo "=========================================================="
echo "        Uninstall Proxy Controller / proxy-lite"
echo "=========================================================="

if [ "$(id -u)" != "0" ]; then
  echo "请使用 root 执行：sudo sh /tmp/uninstall_proxy_controller.sh"
  exit 1
fi

echo "[1/7] 停止并移除守护服务..."

if command -v rc-service >/dev/null 2>&1; then
  rc-service proxy-lite stop 2>/dev/null || true
fi

if command -v rc-update >/dev/null 2>&1; then
  rc-update del proxy-lite default 2>/dev/null || true
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl stop proxy-lite.service 2>/dev/null || true
  systemctl disable proxy-lite.service 2>/dev/null || true
fi

echo "[2/7] 杀掉残留进程..."

if command -v pkill >/dev/null 2>&1; then
  pkill -f "lite_manager.py" 2>/dev/null || true
  pkill -f "proxy_server.py" 2>/dev/null || true
  pkill -f "openvpn.*tun_main" 2>/dev/null || true
  pkill -f "openvpn.*tun_backup" 2>/dev/null || true
else
  ps | grep -E "lite_manager.py|proxy_server.py|openvpn.*tun_main|openvpn.*tun_backup" | grep -v grep | awk '{print $1}' | xargs -r kill 2>/dev/null || true
fi

sleep 1

if command -v pkill >/dev/null 2>&1; then
  pkill -9 -f "lite_manager.py" 2>/dev/null || true
  pkill -9 -f "proxy_server.py" 2>/dev/null || true
  pkill -9 -f "openvpn.*tun_main" 2>/dev/null || true
  pkill -9 -f "openvpn.*tun_backup" 2>/dev/null || true
fi

echo "[3/7] 清理策略路由..."

ip rule del pref 101 2>/dev/null || true
ip rule del pref 102 2>/dev/null || true
ip rule del pref 1101 2>/dev/null || true
ip rule del pref 1102 2>/dev/null || true

ip route flush table 101 2>/dev/null || true
ip route flush table 102 2>/dev/null || true

echo "[4/7] 清理 tun_main / tun_backup 网卡..."

ip link set tun_main down 2>/dev/null || true
ip link set tun_backup down 2>/dev/null || true
ip link delete tun_main 2>/dev/null || true
ip link delete tun_backup 2>/dev/null || true

echo "[5/7] 删除服务文件和程序目录..."

rm -f /etc/init.d/proxy-lite
rm -f /etc/conf.d/proxy-lite
rm -f /lib/systemd/system/proxy-lite.service
rm -f /etc/systemd/system/proxy-lite.service
rm -rf /opt/proxy_lite

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload 2>/dev/null || true
  systemctl reset-failed proxy-lite.service 2>/dev/null || true
fi

echo "[6/7] 移除 sysctl 配置并恢复内核配置..."

rm -f /etc/sysctl.d/99-proxy-lite.conf

if command -v sysctl >/dev/null 2>&1; then
  sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
  sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true
fi

echo "[7/7] 检查残留..."

echo ""
echo "残留进程："
ps | grep -E "lite_manager.py|proxy_server.py|openvpn.*tun_main|openvpn.*tun_backup" | grep -v grep || echo "无"

echo ""
echo "残留路由规则："
ip rule show 2>/dev/null | grep -E "101|102|1101|1102|tun_main|tun_backup" || echo "无"

echo ""
echo "[+] 卸载完成。"
echo "=========================================================="
EOF

chmod +x /tmp/uninstall_proxy_controller.sh
sh /tmp/uninstall_proxy_controller.sh
