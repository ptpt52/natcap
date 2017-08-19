#!/bin/sh

vmroot=`dirname "$0"`
cd "$vmroot"
vmroot=`pwd`
cd -

echo natcap_redirect_port=1080 >/dev/natcap_ctl
ulimit -n 100000
$vmroot/natcapd-server -t 900
echo natcap_redirect_port=0 >/dev/natcap_ctl
