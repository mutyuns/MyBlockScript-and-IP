#!/bin/bash

#---------------------------------------#
# 設定定義
#---------------------------------------#
ALLOW_FILE="/root/allow_ip"
DENY_FILE="/root/deny_ip"
# ブロックしたい国コード
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

dos2unix allow_ip
dos2unix deny_ip
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

# CIDRリスト取得
rm -f ${IP_LIST}
wget -q http://nami.jp/ipv4bycc/cidr.txt.gz
gzip -d -c cidr.txt.gz > ${IP_LIST}
rm -f cidr.txt.gz

# ユーザー定義deny_ipの更新
echo ">>> Updating deny_ip list..."
wget -q -O /root/deny_ip https://raw.githubusercontent.com/mutyuns/MyBlockScript-and-IP/main/deny_ip

# --- [A] ホワイトリスト作成 ---
ipset create whitelist hash:net hashsize 1024 maxelem 65536
ipset add whitelist 127.0.0.1/24
ipset add whitelist 10.0.0.0/8
ipset add whitelist 172.16.0.0/12
ipset add whitelist 192.168.0.0/16

if [ -f "${ALLOW_FILE}" ]; then
    grep -vE "^#|^$" "${ALLOW_FILE}" | while read -r ip; do
        ipset add whitelist "$ip" -exist
    done
fi

# --- [B] ブラックリスト作成 (ユーザー定義用) ---
echo "  - Building blacklist (User Defined)..."
# ユーザー定義用なので標準サイズでOK
ipset create blacklist hash:net hashsize 4096 maxelem 200000

if [ -f "${DENY_FILE}" ]; then
    grep -vE "^#|^$" "${DENY_FILE}" | while read -r ip; do
        ipset add blacklist "$ip" -exist
    done
fi

# --- [C] カントリーブロック作成 (国別大量データ用) ---
echo "  - Building countryblock (GeoIP)..."
# 国別データは膨大になるので maxelem を大きく取る(100万件)
ipset create countryblock hash:net hashsize 4096 maxelem 1000000

for country in "${DROP_COUNTRY_LIST[@]}"; do
    # ここで blacklist ではなく countryblock に追加する
    grep "^${country}" ${IP_LIST} | awk '{print "add countryblock " $2 " -exist"}' | ipset restore
done

#---------------------------------------#
# 3. iptablesルール適用
#---------------------------------------#
echo ">>> Applying iptables rules..."

# 基本ルール
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# ★ipsetフィルタリング (ここを変更)
# 1. ユーザー定義のブラックリストを拒否
iptables -A INPUT -m set --match-set blacklist src -j DROP
# 2. 国別のカントリーブロックを拒否
iptables -A INPUT -m set --match-set countryblock src -j DROP

# ホワイトリスト許可
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
# 4. 設定の保存と永続化設定
#---------------------------------------#
echo ">>> Saving configurations..."

# 1. 現在の設定をファイルに書き出す (全セットが含まれます)
ipset save > ${IPSET_SAVE_FILE}
iptables-save > ${IPTABLES_SAVE_FILE}

# 2. 標準サービスを起動リストから外す
rc-update del ipset default 2>/dev/null || true
rc-update del ipset boot 2>/dev/null || true
rc-update del iptables default 2>/dev/null || true
rc-update del iptables boot 2>/dev/null || true

# 3. local.d 起動スクリプトを作成
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

# 4. localサービスを有効化
rc-update add local default

echo ">>> SUCCESS! Firewall configured."
echo "Check lists with: ipset list blacklist / ipset list countryblock"
echo "Please reboot to verify."
