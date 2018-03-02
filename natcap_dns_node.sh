#!/bin/sh

echo dns_server_node_clean
cat $0 | grep -o '\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)' | while read ip; do
	ping -w1 -c1 $ip 2>&1 >/dev/null && echo dns_server_node_add=$ip
done

exit 0

Level3 209.244.0.3 209.244.0.4
Verisign 64.6.64.6 64.6.65.6
Google 8.8.8.8 8.8.4.4
Quad9 9.9.9.9 149.112.112.112
DNS.WATCH 84.200.69.80 84.200.70.40
Comodo Secure DNS 8.26.56.26 8.20.247.20
OpenDNS Home 208.67.222.222 208.67.220.220
Norton ConnectSafe 199.85.126.10 199.85.127.10
GreenTeamDNS 81.218.119.11 209.88.198.133
SafeDNS 195.46.39.39 195.46.39.40
OpenNIC 69.195.152.204 23.94.60.240
SmartViper 208.76.50.50 208.76.51.51
Dyn 216.146.35.35 216.146.36.36
FreeDNS 37.235.1.174 37.235.1.177
Alternate DNS 198.101.242.72 23.253.163.53
Yandex.DNS 77.88.8.8 77.88.8.1
UncensoredDNS 91.239.100.100 89.233.43.71
Hurricane Electric 74.82.42.42
puntCAT 109.69.8.51
Neustar 156.154.70.1 156.154.71.1
