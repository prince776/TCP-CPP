#!/bin/bash

sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0
echo "Added ifconfig"
# config command to be used in mac, doesn't work though.
# sudo ifconfig tun0 inet 10.0.0.1 10.0.0.2 up
# 
# ssh syncing command used to dev
# rsync -av --exclude='build/'  --exclude='.git/' --exclude='.cache/'  --exclude='dependencies'  ~/projects/netstack user@ip:/home/user
