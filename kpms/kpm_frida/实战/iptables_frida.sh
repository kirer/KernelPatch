#!/system/bin/sh
# iptables_frida.sh - 只拦截非 root 进程访问 frida 端口
# root/system 放行（frida-server 自身通信不受影响）
# 游戏等普通 app 被拦截（无法端口扫描检测 frida）
IPT=/system/bin/iptables
$IPT -F OUTPUT 2>/dev/null
for port in 27042 27043 23946 31415; do
    $IPT -A OUTPUT -p tcp --dport $port -m owner --uid-owner 0-9999 -j ACCEPT
    $IPT -A OUTPUT -p tcp --dport $port -j REJECT --reject-with tcp-reset
done
echo "Smart frida iptables rules installed."
$IPT -L OUTPUT -n | grep -E '27042|27043|23946|31415'
