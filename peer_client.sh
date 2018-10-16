#!/bin/bash

SERVER=ec2ns.ptpt52.com

while :; do
	timeout 30 ping -t1 -s16 -c16 $SERVER
done
