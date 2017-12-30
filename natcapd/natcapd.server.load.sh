#!/bin/sh

vmroot=`dirname "$0"`
cd "$vmroot"
vmroot=`pwd`
cd -

test -c /dev/natcap_ctl && echo natcap_redirect_port=1080 >/dev/natcap_ctl
ulimit -n 100000
$vmroot/natcapd-server -t 900
test -c /dev/natcap_ctl && echo natcap_redirect_port=0 >/dev/natcap_ctl
