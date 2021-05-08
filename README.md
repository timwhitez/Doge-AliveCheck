# Doge-AliveCheck
Use ICMP requests to check the alive subnet.

### Build
go build -ldflags "-s -w" -trimpath

### Usage
Doge-AliveCheck.exe
无参数则根据当前网段信息进行扫描...

Doge-AliveCheck.exe all
all参数扫描10.0.0.0-10.255.255.255; 172.16.0.0-172.31.255.255; 192.168.0.0-192.168.255.255

Doge-AliveCheck.exe 211.111.1.1
非常规内网ip默认扫输入的ip对应b段
