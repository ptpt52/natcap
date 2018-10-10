#!/bin/bash

SERVER=1.2.3.4

while :; do
	timeout 30 ping -t1 -s16 -c16 $SERVER
done
