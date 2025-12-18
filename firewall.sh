#!/bin/bash

#---------------------------------------#
# 設定定義
#---------------------------------------#
ALLOW_FILE="/root/allow_ip"
DENY_FILE="/root/deny_ip"
DROP_COUNTRY_LIST=("CN" "RU" "KR" "NK")
IP_LIST="/tmp/cidr.txt"

# 保存先パス (固定)
IPSET_SAVE_FILE="/etc/ipset.conf"
IPTABLES_SAVE_FILE="/etc/iptables.rules"

#---------------------------------------#
# 1. 準備とリセット
#---------------------------------------#
echo ">>> Pre-flight check..."
apk add wget ipset iptables
modprobe ip_set
modprobe ip_set_hash_net
modprobe netfilter_xt_set

# インターネット接続確認
if ! ping -c 1 8.8.8.8 &> /dev/null; then
    echo "ERROR: Network is unreachable."
    exit 1
fi

# 既存の設定を全クリア
rc-service iptables stop 2>/dev/null
rc-service ipset stop 2>/dev/null
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F
iptables -X
ipset destroy 2>/dev/null

#---------------------------------------#
# 2. IPリスト作成 (メモリ上)
#---------------------------------------#
echo ">>> Configuring IP Sets..."

# リスト取得
rm -f ${IP_LIST}
wget -q http://nami.jp/ipv4bycc/cidr.txt.gz
gzip -d -c cidr.txt.gz > ${IP_LIST}
rm -f cidr.txt.gz

echo ">>> Updating deny_ip list..."
wget -q -O /root/deny_ip https://raw.githubusercontent.com/mutyuns/MyBlockScript-and-IP/main/deny_ip

# --- ホワイトリスト ---
ipset create whitelist hash:net
ipset add whitelist 127.0.0.1/24
ipset add whitelist 10.0.0.0/8
ipset add whitelist 172.16.0.0/12
ipset add whitelist 192.168.0.0/16

if [ -f "${ALLOW_FILE}" ]; then
    grep -vE "^#|^$" "${ALLOW_FILE}" | while read -r ip; do
        ipset add whitelist "$ip" -exist
    done
fi

# --- ブラックリスト ---
echo "  - Building blacklist..."
ipset create blacklist hash:net

if [ -f "${DENY_FILE}" ]; then
    grep -vE "^#|^$" "${DENY_FILE}" | while read -r ip; do
        ipset add blacklist "$ip" -exist
    done
fi

for country in "${DROP_COUNTRY_LIST[@]}"; do
    grep "^${country}" ${IP_LIST} | awk '{print "add blacklist " $2 " -exist"}' | ipset restore
done

#---------------------------------------#
# 3. iptablesルール適用
#---------------------------------------#
echo ">>> Applying iptables rules..."

# 基本ルール
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# ipsetフィルタリング
iptables -A INPUT -m set --match-set blacklist src -j DROP
iptables -A INPUT -p tcp --dport 10022 -m set --match-set whitelist src -j ACCEPT
iptables -A INPUT -p tcp --dport 9090 -m set --match-set whitelist src -j ACCEPT

# Web公開
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p udp --dport 443 -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT

# MSS Clamping
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# 拒否ポリシー
iptables -P INPUT DROP
iptables -P FORWARD DROP

#---------------------------------------#
# 4. 設定の保存と永続化設定 (★ここが修正のキモ)
#---------------------------------------#
echo ">>> Saving configurations..."

# 1. 現在の設定をファイルに書き出す
ipset save > ${IPSET_SAVE_FILE}
iptables-save > ${IPTABLES_SAVE_FILE}

# 2. 標準サービスを起動リストから外す
# (タイミング問題の原因になるため、これらは使いません)
rc-update del ipset default 2>/dev/null || true
rc-update del ipset boot 2>/dev/null || true
rc-update del iptables default 2>/dev/null || true
rc-update del iptables boot 2>/dev/null || true

# 3. local.d 起動スクリプトを作成
# Alpineでは /etc/local.d/*.start が起動時に実行されます
echo ">>> Setting up persistent boot script in /etc/local.d/..."

cat <<EOF > /etc/local.d/firewall.start
#!/bin/sh
# Firewall Startup Script created by firewall.sh

# 1. Load Modules
modprobe ip_set
modprobe ip_set_hash_net
modprobe iptable_filter
modprobe iptable_mangle

# 2. Restore IP Sets
if [ -f ${IPSET_SAVE_FILE} ]; then
    echo "Restoring IP Sets..."
    ipset restore -f ${IPSET_SAVE_FILE}
fi

# 3. Restore iptables Rules
if [ -f ${IPTABLES_SAVE_FILE} ]; then
    echo "Restoring iptables rules..."
    iptables-restore < ${IPTABLES_SAVE_FILE}
fi
EOF

# 実行権限を付与
chmod +x /etc/local.d/firewall.start

# 4. localサービスを有効化 (これが起動時に上記スクリプトを実行します)
rc-update add local default

echo ">>> SUCCESS! Firewall configured using local.d persistence."
echo "Please reboot to verify."
