#!/bin/bash

echo 1 > /proc/sys/net/ipv4/ip_forward

iptables -F
iptables -F -t nat
iptables -P INPUT ACCEPT
iptables -P FORWARD DROP

iptables -I FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -A FORWARD -m mark --mark 0x99 -j ACCEPT
iptables -t nat -A POSTROUTING -m mark --mark 0x99 -j MASQUERADE


rmmod natcap >/dev/null 2>&1
( modprobe natcap mode=2 || insmod ./natcap.ko mode=2 ) && {
cat <<EOF >>/dev/natcap_ctl
clean
debug=3
disabled=0
server_persist_timeout=6
server 1.2.3.4:65535-e
EOF
}
