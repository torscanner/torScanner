#!/bin/bash

base_socks_port=$2
base_control_port=$3
user=$4

# Create data directory if it doesn't exist
if [ ! -d "data" ]; then
	mkdir "data"
fi

s=$(($1-1))
for i in `seq 0 $s`;

do
	j=$((i+1))
	socks_port=$((base_socks_port+i))
	control_port=$((base_control_port+i))
	if [ ! -d "data/tor$i" ]; then
		echo "Creating directory data/tor$i"
		mkdir "data/tor$i"
	fi
	tor --User $user --DataDirectory /opt/data/tor$i  --CookieAuthentication 0 --HashedControlPassword "" --ControlPort $control_port --PidFile tor$i.pid --SocksPort $socks_port --RunAsDaemon 1 >/dev/null 2>&1
done
