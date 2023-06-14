#!/bin/bash

sudo ./build/netstack &
pid=$!
echo "pid: ${pid}"
sleep 1
sudo ifconfig tun0 inet 10.0.0.1 10.0.0.2 up
echo "Added ifconfig"
trap "sudo kill $pid" INT TERM
wait $pid