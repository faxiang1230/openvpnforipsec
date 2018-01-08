# client log
```
linux@linux-VirtualBox:~/source/easy-rsa/easy-rsa/2.0/keys$ sudo openvpn --config client.conf
Mon Jan  8 22:13:14 2018 OpenVPN 2.4.4 x86_64-unknown-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Jan  3 2018
Mon Jan  8 22:13:14 2018 library versions: OpenSSL 1.0.2g  1 Mar 2016, LZO 2.08
Mon Jan  8 22:13:14 2018 Outgoing Control Channel Authentication: Using 160 bit message hash 'SHA1' for HMAC authentication
Mon Jan  8 22:13:14 2018 Incoming Control Channel Authentication: Using 160 bit message hash 'SHA1' for HMAC authentication
Mon Jan  8 22:13:14 2018 TCP/UDP: Preserving recently used remote address: [AF_INET]10.0.0.6:1194
Mon Jan  8 22:13:14 2018 Socket Buffers: R=[212992->212992] S=[212992->212992]
Mon Jan  8 22:13:14 2018 UDP link local: (not bound)
Mon Jan  8 22:13:14 2018 UDP link remote: [AF_INET]10.0.0.6:1194
Mon Jan  8 22:13:14 2018 TLS: Initial packet from [AF_INET]10.0.0.6:1194, sid=2c2c5d69 785e2f50
Mon Jan  8 22:13:14 2018 VERIFY OK: depth=1, C=CN, ST=Beijing, L=Beijing, O=TsinghuaUniversity, OU=OPENTHOS, CN=TsinghuaUniversity CA, name=EasyRSA, emailAddress=wangjianxing5210@163.com
Mon Jan  8 22:13:14 2018 VERIFY KU OK
Mon Jan  8 22:13:14 2018 Validating certificate extended key usage
Mon Jan  8 22:13:14 2018 ++ Certificate has EKU (str) TLS Web Server Authentication, expects TLS Web Server Authentication
Mon Jan  8 22:13:14 2018 VERIFY EKU OK
Mon Jan  8 22:13:14 2018 VERIFY OK: depth=0, C=CN, ST=Beijing, L=Beijing, O=TsinghuaUniversity, OU=OPENTHOS, CN=server, name=EasyRSA, emailAddress=wangjianxing5210@163.com
Mon Jan  8 22:13:14 2018 Control Channel: TLSv1.2, cipher TLSv1/SSLv3 ECDHE-RSA-AES256-GCM-SHA384, 2048 bit RSA
Mon Jan  8 22:13:14 2018 [server] Peer Connection Initiated with [AF_INET]10.0.0.6:1194
Mon Jan  8 22:13:15 2018 SENT CONTROL [server]: 'PUSH_REQUEST' (status=1)
Mon Jan  8 22:13:15 2018 PUSH: Received control message: 'PUSH_REPLY,route 0.0.0.0 0.0.0.0,route 10.8.0.1,topology net30,ping 10,ping-restart 120,ifconfig 10.8.0.6 10.8.0.5,peer-id 1,cipher AES-256-GCM'
Mon Jan  8 22:13:15 2018 OPTIONS IMPORT: timers and/or timeouts modified
Mon Jan  8 22:13:15 2018 OPTIONS IMPORT: --ifconfig/up options modified
Mon Jan  8 22:13:15 2018 OPTIONS IMPORT: route options modified
Mon Jan  8 22:13:15 2018 OPTIONS IMPORT: peer-id set
Mon Jan  8 22:13:15 2018 OPTIONS IMPORT: adjusting link_mtu to 1624
Mon Jan  8 22:13:15 2018 OPTIONS IMPORT: data channel crypto options modified
Mon Jan  8 22:13:15 2018 Data Channel: using negotiated cipher 'AES-256-GCM'
Mon Jan  8 22:13:15 2018 Outgoing Data Channel: Cipher 'AES-256-GCM' initialized with 256 bit key
Mon Jan  8 22:13:15 2018 Incoming Data Channel: Cipher 'AES-256-GCM' initialized with 256 bit key
Mon Jan  8 22:13:15 2018 ROUTE_GATEWAY 10.0.0.1/255.255.255.0 IFACE=enp0s3 HWADDR=08:00:27:fb:f4:db
Mon Jan  8 22:13:15 2018 TUN/TAP device tun0 opened
Mon Jan  8 22:13:15 2018 TUN/TAP TX queue length set to 100
Mon Jan  8 22:13:15 2018 do_ifconfig, tt->did_ifconfig_ipv6_setup=0
Mon Jan  8 22:13:15 2018 /sbin/ifconfig tun0 10.8.0.6 pointopoint 10.8.0.5 mtu 1500
Mon Jan  8 22:13:15 2018 /sbin/route add -net 10.0.0.6 netmask 255.255.255.255 dev enp0s3
Mon Jan  8 22:13:15 2018 /sbin/route add -net 0.0.0.0 netmask 128.0.0.0 gw 10.8.0.5
Mon Jan  8 22:13:15 2018 /sbin/route add -net 128.0.0.0 netmask 128.0.0.0 gw 10.8.0.5
Mon Jan  8 22:13:15 2018 /sbin/route add -net 0.0.0.0 netmask 0.0.0.0 gw 10.8.0.5
Mon Jan  8 22:13:15 2018 /sbin/route add -net 10.8.0.1 netmask 255.255.255.255 gw 10.8.0.5
Mon Jan  8 22:13:15 2018 WARNING: this configuration may cache passwords in memory -- use the auth-nocache option to prevent this
Mon Jan  8 22:13:15 2018 Initialization Sequence Completed
```
route:
```
linux@linux-VirtualBox:~/source/easy-rsa/easy-rsa/2.0/keys$ route
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         10.8.0.5        128.0.0.0       UG    0      0        0 tun0
default         10.8.0.5        0.0.0.0         UG    0      0        0 tun0
default         10.0.0.1        0.0.0.0         UG    100    0        0 enp0s3
10.0.0.0        *               255.255.255.0   U     100    0        0 enp0s3
10.0.0.6        *               255.255.255.255 UH    0      0        0 enp0s3
10.8.0.1        10.8.0.5        255.255.255.255 UGH   0      0        0 tun0
10.8.0.5        *               255.255.255.255 UH    0      0        0 tun0
128.0.0.0       10.8.0.5        128.0.0.0       UG    0      0        0 tun0
link-local      *               255.255.0.0     U     1000   0        0 enp0s3
```
it looks like that route to tun device and then encrypt,send it via physical net devices
