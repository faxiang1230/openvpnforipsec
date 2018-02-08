sudo ip addr add 192.168.1.1/24 dev tun0
sudo ifconfig tun0 up
sudo route add default gw 192.168.1.1 netmask 0.0.0.0
#sudo iptable -t nat -A PREROUTING -p 50 -j DNAT --to-destination 192.168.1.2
