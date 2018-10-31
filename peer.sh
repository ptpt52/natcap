#!/bin/bash

echo 1 > /proc/sys/net/ipv4/ip_forward

iptables -F
iptables -F -t nat
iptables -P FORWARD DROP
iptables -P INPUT ACCEPT

iptables -I FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -I FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 

iptables -I FORWARD -m mark --mark 0x99 -j ACCEPT
iptables -t nat -I POSTROUTING -m mark --mark 0x99 -j MASQUERADE

modprobe ip_set
rmmod natcap >/dev/null 2>&1
( modprobe natcap mode=5 debug=3 2>/dev/null || insmod ./natcap.ko mode=5 debug=3 ) && {
cat <<EOF >>/dev/natcap_peer_ctl
local_target=0.0.0.0:22
peer_sni_auth=1
EOF
}
