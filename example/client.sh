sudo ip addr add 192.168.1.10/24 dev tun0
sudo ifconfig tun0 up
sudo route add default gw 192.168.1.10 netmask 0.0.0.0
