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
	*)
		echo "peer_ctl msg <mac>"
		echo "peer_ctl conn <mac>"
		echo "peer_ctl ps <mac>"
	;;
esac
