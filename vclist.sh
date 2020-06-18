#!/bin/bash

# load && run
modprobe ip_set
rmmod natcap >/dev/null 2>&1
( modprobe natcap auth_enabled=1 mode=1 >/dev/null || insmod ./natcap.ko auth_enabled=1 mode=1 ) && {
cat <<EOF >>/dev/natcap_ctl
debug=3
disabled=0
EOF
}

ipset create vclist hash:mac hashsize 1024 maxelem 65536

