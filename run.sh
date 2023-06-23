#!/bin/bash
ext=$?
if [[ $ext -ne 0 ]]; then
	exit $ext
fi
sudo ./build/netstack &
pid=$!
sleep 3
# sudo ifconfig utun9 inet 10.0.0.1 10.0.0.2 up
sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0
echo "Added ifconfig"
echo "pid: ${pid}"
trap "sudo kill $pid" INT TERM
wait $pid
