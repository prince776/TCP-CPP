#!/bin/bash

sudo ./build/netstack &
pid=$!
sleep 3
sudo ifconfig tun0 inet 10.0.0.1 10.0.0.2 up
echo "Added ifconfig"
echo "pid: ${pid}"
trap "sudo kill $pid" INT TERM
wait $pid
