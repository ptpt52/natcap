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

iptables -A FORWARD -s 192.168.0.0/16 -j ACCEPT
iptables -t nat -A POSTROUTING -s 192.168.0.0/16 -j MASQUERADE

ipset destroy cniplist
ipset destroy gfwlist
ipset destroy udproxylist
ipset restore -f cniplist.set
ipset create gfwlist iphash
ipset create udproxylist iphash
ipset add udproxylist 8.8.8.8

SERVER=45.32.63.59
iptables -t nat -A OUTPUT -d 8.8.8.8 -p udp --dport 53 -j DNAT --to-destination $SERVER:5353
iptables -t nat -A PREROUTING -d 8.8.8.8 -p udp --dport 53 -j DNAT --to-destination $SERVER:5353

cp accelerated-domains.gfwlist.dnsmasq.conf /etc/dnsmasq.d/
service dnsmasq restart

rmmod natcap >/dev/null 2>&1
insmod ./natcap.ko mode=0 && {
cat <<EOF >>/dev/natcap_ctl

clean
debug=3

server_persist_timeout=6
server 192.241.223.185:65535-e
server 45.32.63.59:65535-e
EOF
}
