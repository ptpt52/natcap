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

# load && run
rmmod natcap >/dev/null 2>&1
( modprobe natcap mode=1 >/dev/null || insmod ./natcap.ko mode=1 ) && {
cat <<EOF >>/dev/natcap_ctl
debug=3
disabled=0
EOF

# reload natcapd-server
killall natcapd-server 2>/dev/null
sh ./natcapd/natcapd.server.load.sh &

}

sysctl_setup()
{
	cat | while read line; do
		sysctl -w $line
	done
}

# basic system config setup, enable bbr
sysctl_setup << EOF
kernel.panic=3
net.ipv4.conf.default.arp_ignore=1
net.ipv4.conf.all.arp_ignore=1
net.ipv4.ip_forward=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.igmp_max_memberships=100
net.ipv4.tcp_max_syn_backlog=512
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_keepalive_time=120
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_sack=1
net.ipv4.tcp_dsack=1
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_congestion_control=bbr
net.netfilter.nf_conntrack_acct=1
net.netfilter.nf_conntrack_checksum=0
net.netfilter.nf_conntrack_max=655360
net.netfilter.nf_conntrack_tcp_timeout_established=7440
net.netfilter.nf_conntrack_udp_timeout=60
net.netfilter.nf_conntrack_udp_timeout_stream=180
net.core.somaxconn=2048
net.core.default_qdisc=fq
EOF
