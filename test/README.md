# 正常处理
tcpdump能够观察到

## IPv4 分片测试
sudo hping3 -1 192.168.1.10 --data 1473  -c 1 # ICMP 分片 (1473 + 8 + 20 > 1500)

## TCP 分片测试
sudo hping3 -S 192.168.1.10 -p 80 --data 1473 -c 1

## 发送接近最大尺寸的 ICMP 包（65507 字节 payload）
sudo hping3 -1  192.168.1.10  --data 65495 -c 1

## 发送大 TCP SYN 包（payload 65400）
sudo hping3 -S  192.168.1.10  -p 80 --data 65400 -c 1

## IPv6 分片测试
sudo hping3 -6 -1 2001:db8::1 --data 1473
