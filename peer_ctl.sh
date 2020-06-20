#!/bin/sh

#ping6 ff99:aabb:ccdd:eeff:: -t1 -s1 -c1 -W1
send_msg()
{
	echo $1 | sed 's/:/ /g;s/-/ /g;' | tr A-F a-f | while read m0 m1 m2 m3 m4 m5; do
		test -n "$m0" && \
		test -n "$m1" && \
		test -n "$m2" && \
		test -n "$m3" && \
		test -n "$m4" && \
		test -n "$m5" && {
			ping6 ff99:$m0$m1:$m2$m3:$m4$m5:: -t1 -s1 -c1 -W1
		}
	done
}

send_conn()
{
	test -c /dev/natcap_peer_ctl || return
	echo $1 | sed 's/:/ /g;s/-/ /g;' | tr A-F a-f | while read m0 m1 m2 m3 m4 m5; do
		test -n "$m0" && \
		test -n "$m1" && \
		test -n "$m2" && \
		test -n "$m3" && \
		test -n "$m4" && \
		test -n "$m5" && {
			echo "echo KN=255.255.255.255:22 MAC=$m0:$m1:$m2:$m3:$m4:$m5 LP=997 >/dev/natcap_peer_ctl"
			echo KN=255.255.255.255:22 MAC=$m0:$m1:$m2:$m3:$m4:$m5 LP=997 >/dev/natcap_peer_ctl
		}
	done
}

send_ps()
{
	test -c /dev/natcap_peer_ctl || return
	echo $1 | sed 's/:/ /g;s/-/ /g;' | tr A-F a-f | while read m0 m1 m2 m3 m4 m5; do
		test -n "$m0" && \
		test -n "$m1" && \
		test -n "$m2" && \
		test -n "$m3" && \
		test -n "$m4" && \
		test -n "$m5" && {
			cat /dev/natcap_peer_ctl | grep $m0:$m1:$m2:$m3:$m4:$m5
		}
	done
}

list_cli()
{
	(cat /proc/net/nf_conntrack 2>/dev/null || conntrack -L 2>/dev/null) | grep -o "udp.*src=.*dst=127.255.255.254 sport=.* dport=65535 .*src=127.255.255.254 dst=.* sport=65535 dport=.*" | while read _ _ timeout src _ sport _ _ _ _ _ _ _ _ _ _ mark _ _; do
		things=`echo $timeout $src $sport | grep -o [0-9]*`
		things=`echo $things`
		_src=`printf "src=%u.%u.%u.%u" $(((mark&0xff000000)>>24)) $(((mark&0x00ff0000)>>16)) $(((mark&0x0000ff00)>>8)) $(((mark&0x000000ff)>>0))`
		echo "$things" | while read T ip1 ip2 ip3 ip4 port; do
			printf "mac=%02x:%02x:%02x:%02x:%02x:%02x %-19s T=%d\n" $ip1 $ip2 $ip3 $ip4 $((port/256)) $((port&255)) $_src $T
		done
	done
}

case $1 in
	msg)
		send_msg $2
	;;
	conn)
		send_conn $2
	;;
	ps)
		send_ps $2
	;;
	list|list_cli)
		list_cli
	;;
	*)
		echo "peer_ctl msg <mac>"
		echo "peer_ctl conn <mac>"
		echo "peer_ctl ps <mac>"
		echo "peer_ctl list_cli"
	;;
esac
