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


ipset destroy cniplist
ipset destroy gfwlist
ipset destroy udproxylist

echo 'create cniplist hash:net family inet hashsize 4096 maxelem 65536' >/tmp/cniplist.set
cat cniplist.set | sed 's/^/add cniplist /' >>/tmp/cniplist.set
ipset restore -f /tmp/cniplist.set
rm -f /tmp/cniplist.set

ipset create gfwlist iphash
ipset create udproxylist iphash
ipset add udproxylist 8.8.8.8

rmmod natcap >/dev/null 2>&1
( modprobe natcap mode=5 2>/dev/null || insmod ./natcap.ko mode=5 ) && {
cat <<EOF >>/dev/natcap_ctl
clean
debug=3
EOF
}
