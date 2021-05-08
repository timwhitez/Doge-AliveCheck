# Doge-AliveCheck
Use ICMP requests to check the alive subnet.

### Build
go build -ldflags "-s -w" -trimpath

### Usage
Doge-AliveCheck.exe
default scan...

Doge-AliveCheck.exe all
full scan 10.0.0.0-10.255.255.255; 172.16.0.0-172.31.255.255; 192.168.0.0-192.168.255.255

Doge-AliveCheck.exe 211.111.1.1
scan class b subnet from input ip
