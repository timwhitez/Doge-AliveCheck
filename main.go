package main

import (
	"errors"
	"fmt"
	"golang.org/x/net/icmp"
	"log"
	"math/rand"
	"net"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var AliveHosts []string

var SysInfo = GetSys()

type SystemInfo struct {
	OS       string
	HostName string
	Groupid  string
	Userid   string
	Username string
}

func GetSys() SystemInfo {
	var sysinfo SystemInfo

	sysinfo.OS = runtime.GOOS
	name, err := os.Hostname()
	if err == nil {
		sysinfo.HostName = name
	} else {
		name = "none"
	}

	u, err := user.Current()
	if err == nil {
		sysinfo.Groupid = u.Gid
		sysinfo.Userid = u.Uid
		sysinfo.Username = u.Username
	} else {
		sysinfo.Groupid = "1"
		sysinfo.Userid = "1"
		sysinfo.Username = name
	}

	return sysinfo
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func IcmpCheck(hostslist []string) {
	TmpHosts := make(map[string]struct{})
	var chanHosts = make(chan string)
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	endflag := false
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			if endflag == true {
				return
			}
			msg := make([]byte, 100)
			_, sourceIP, _ := conn.ReadFrom(msg)
			if sourceIP != nil {
				chanHosts <- sourceIP.String()
			}
		}
	}()

	go func() {
		for ip := range chanHosts {
			if _, ok := TmpHosts[ip]; !ok {
				TmpHosts[ip] = struct{}{}
				ip1 := strings.Split(ip,".")[0]
				ip2 := strings.Split(ip,".")[1]
				ip3 := strings.Split(ip,".")[2]
				cidr := ip1+"."+ip2+"."+ip3+".1/24"
				if !stringInSlice(cidr,AliveHosts){
					fmt.Println(cidr)
				}
				AliveHosts = append(AliveHosts, cidr)
			}
		}
	}()

	for _, host0 := range hostslist {
		write(host0, conn)
	}

	if len(hostslist) > 255 {
		time.Sleep(30 * time.Second)
	} else {
		time.Sleep(15 * time.Second)
	}

	endflag = true
	close(chanHosts)
	conn.Close()
}

func write(ip string, conn *icmp.PacketConn) {
	dst, _ := net.ResolveIPAddr("ip", ip)
	IcmpByte := []byte{8, 0, 247, 255, 0, 0, 0, 0}
	conn.WriteTo(IcmpByte, dst)
}


func ICMPRun(hostslist []string) []string {
	if SysInfo.OS == "windows" {
		IcmpCheck(hostslist)
	} else if SysInfo.OS == "linux" {
		if SysInfo.Groupid == "0" || SysInfo.Userid == "0" || SysInfo.Username == "root" {
				IcmpCheck(hostslist)
		} else {
			fmt.Println("The current user permissions unable to send icmp packets")
		}
	} else if SysInfo.OS == "darwin" {
		if SysInfo.Groupid == "0" || SysInfo.Userid == "0" || SysInfo.Username == "root" {
				IcmpCheck(hostslist)
		} else {
			fmt.Println("The current user permissions unable to send icmp packets")
		}
	}
	return AliveHosts
}

var ParseIPErr = errors.New(" ip parsing error\n" +
	"format: \n" +
	"192.168.1.1\n" )

func ParseIPone(ip string) (error) {
	testIP := net.ParseIP(ip)
	if testIP == nil {
		return ParseIPErr
	}
	return nil
}


func GetInternalIP() (string, error) {
	// 思路来自于Python版本的内网IP获取，其他版本不准确
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", errors.New("internal IP fetch failed, detail:" + err.Error())
	}
	defer conn.Close()

	// udp 面向无连接，所以这些东西只在你本地捣鼓
	res := conn.LocalAddr().String()
	res = strings.Split(res, ":")[0]
	return res, nil
}

func RandInt(min, max int) int {
	if min >= max || min == 0 || max == 0 {
		return max
	}
	return rand.Intn(max-min) + min
}


func cidrToalive(cidr string)([]string){
	e := ParseIPone(cidr)
	if e != nil{
		fmt.Println(e)
		return nil
	}
	ip1 := strings.Split(cidr,".")[0]
	ip2 := strings.Split(cidr,".")[1]

	var ipList []string

	if ip1 == "10"{
		for i0:= 0;i0 <= 255 ;i0++ {
			for i1 := 0; i1 <= 255; i1++ {
				ipList = append(ipList, ip1+"."+strconv.Itoa(i0)+"."+strconv.Itoa(i1)+".0")
				ipList = append(ipList, ip1+"."+strconv.Itoa(i0)+"."+strconv.Itoa(i1)+".1")
				ipList = append(ipList, ip1+"."+strconv.Itoa(i0)+"."+strconv.Itoa(i1)+".2")
				ipList = append(ipList, ip1+"."+strconv.Itoa(i0)+"."+strconv.Itoa(i1)+".254")
				ipList = append(ipList, ip1+"."+strconv.Itoa(i0)+"."+strconv.Itoa(i1)+".255")
				ipList = append(ipList, ip1+"."+strconv.Itoa(i0)+"."+strconv.Itoa(i1)+"."+strconv.Itoa(RandInt(3, 253)))
				ipList = append(ipList, ip1+"."+strconv.Itoa(i0)+"."+strconv.Itoa(i1)+"."+strconv.Itoa(RandInt(3, 253)))
				ipList = append(ipList, ip1+"."+strconv.Itoa(i0)+"."+strconv.Itoa(i1)+"."+strconv.Itoa(RandInt(3, 253)))
				ipList = append(ipList, ip1+"."+strconv.Itoa(i0)+"."+strconv.Itoa(i1)+"."+strconv.Itoa(RandInt(3, 253)))
				ipList = append(ipList, ip1+"."+strconv.Itoa(i0)+"."+strconv.Itoa(i1)+"."+strconv.Itoa(RandInt(3, 253)))
			}
		}
		return ipList
	}
	if ip1 == "172"{
		ip2tmp,_ := strconv.Atoi(ip2)
		if ip2tmp >= 16 && ip2tmp <= 31{
			for i0:= 16;i0 <= 31;i0++ {
				for i1 := 0; i1 <= 255; i1++ {
					ipList = append(ipList, ip1+"."+strconv.Itoa(i0)+"."+strconv.Itoa(i1)+".0")
					ipList = append(ipList, ip1+"."+strconv.Itoa(i0)+"."+strconv.Itoa(i1)+".1")
					ipList = append(ipList, ip1+"."+strconv.Itoa(i0)+"."+strconv.Itoa(i1)+".2")
					ipList = append(ipList, ip1+"."+strconv.Itoa(i0)+"."+strconv.Itoa(i1)+".254")
					ipList = append(ipList, ip1+"."+strconv.Itoa(i0)+"."+strconv.Itoa(i1)+".255")
					ipList = append(ipList, ip1+"."+strconv.Itoa(i0)+"."+strconv.Itoa(i1)+"."+strconv.Itoa(RandInt(3, 253)))
					ipList = append(ipList, ip1+"."+strconv.Itoa(i0)+"."+strconv.Itoa(i1)+"."+strconv.Itoa(RandInt(3, 253)))
					ipList = append(ipList, ip1+"."+strconv.Itoa(i0)+"."+strconv.Itoa(i1)+"."+strconv.Itoa(RandInt(3, 253)))
					ipList = append(ipList, ip1+"."+strconv.Itoa(i0)+"."+strconv.Itoa(i1)+"."+strconv.Itoa(RandInt(3, 253)))
					ipList = append(ipList, ip1+"."+strconv.Itoa(i0)+"."+strconv.Itoa(i1)+"."+strconv.Itoa(RandInt(3, 253)))
				}
			}
			return ipList
		}
	}
	if ip1 == "192" && ip2 == "168"{
		for i1 := 0;i1 <= 255;i1++ {
			ipList = append(ipList, "192.168."+strconv.Itoa(i1)+".0")
			ipList = append(ipList, "192.168."+strconv.Itoa(i1)+".1")
			ipList = append(ipList, "192.168."+strconv.Itoa(i1)+".2")
			ipList = append(ipList, "192.168."+strconv.Itoa(i1)+".254")
			ipList = append(ipList, "192.168."+strconv.Itoa(i1)+".255")
			ipList = append(ipList, "192.168."+strconv.Itoa(i1)+strconv.Itoa(RandInt(3, 253)))
			ipList = append(ipList, "192.168."+strconv.Itoa(i1)+strconv.Itoa(RandInt(3, 253)))
			ipList = append(ipList, "192.168."+strconv.Itoa(i1)+strconv.Itoa(RandInt(3, 253)))
			ipList = append(ipList, "192.168."+strconv.Itoa(i1)+strconv.Itoa(RandInt(3, 253)))
			ipList = append(ipList, "192.168."+strconv.Itoa(i1)+strconv.Itoa(RandInt(3, 253)))
		}
		return ipList
	}
	for i1 := 0;i1 <= 255;i1++ {
		ipList = append(ipList, ip1+"."+ip2+"."+strconv.Itoa(i1)+".0")
		ipList = append(ipList, ip1+"."+ip2+"."+strconv.Itoa(i1)+".1")
		ipList = append(ipList, ip1+"."+ip2+"."+strconv.Itoa(i1)+".2")
		ipList = append(ipList, ip1+"."+ip2+"."+strconv.Itoa(i1)+".254")
		ipList = append(ipList, ip1+"."+ip2+"."+strconv.Itoa(i1)+".255")
		ipList = append(ipList, ip1+"."+ip2+"."+strconv.Itoa(i1)+strconv.Itoa(RandInt(3, 253)))
		ipList = append(ipList, ip1+"."+ip2+"."+strconv.Itoa(i1)+strconv.Itoa(RandInt(3, 253)))
		ipList = append(ipList, ip1+"."+ip2+"."+strconv.Itoa(i1)+strconv.Itoa(RandInt(3, 253)))
		ipList = append(ipList, ip1+"."+ip2+"."+strconv.Itoa(i1)+strconv.Itoa(RandInt(3, 253)))
		ipList = append(ipList, ip1+"."+ip2+"."+strconv.Itoa(i1)+strconv.Itoa(RandInt(3, 253)))
	}
	return ipList
}





func main() {
	var Hosts []string
	if len(os.Args)==1{
		inIP,err := GetInternalIP()
		if err != nil{
			intSlice := strings.Split(os.Args[0],"\\")
			fmt.Println("无参数则根据当前网段信息进行扫描")
			fmt.Println("Default Scan\n")

			fmt.Println(intSlice[len(intSlice)-1]+" all")
			fmt.Println("10.0.0.0-10.255.255.255; 172.16.0.0-172.31.255.255; 192.168.0.0-192.168.255.255\n")


			fmt.Println(intSlice[len(intSlice)-1]+" 211.111.1.1")
			fmt.Println("非常规内网ip默认扫b段")
			fmt.Println("scan class b subnet from input ip\n")
			return
		}
		fmt.Println("根据当前网段信息进行扫描...")
		fmt.Println("in-ip: "+inIP)
		Hosts = cidrToalive(inIP)
		if Hosts != nil {
			ICMPRun(Hosts)
			ICMPRun(Hosts)
			ICMPRun(Hosts)
		}
	}else if len(os.Args) == 2{
		if os.Args[1] == "-h" || os.Args[1] == "help"{
			intSlice := strings.Split(os.Args[0],"\\")
			fmt.Println(intSlice[len(intSlice)-1])
			fmt.Println("无参数则根据当前网段信息进行扫描")
			fmt.Println("Default Scan\n")

			fmt.Println(intSlice[len(intSlice)-1]+" all")
			fmt.Println("10.0.0.0-10.255.255.255; 172.16.0.0-172.31.255.255; 192.168.0.0-192.168.255.255\n")


			fmt.Println(intSlice[len(intSlice)-1]+" 211.111.1.1")
			fmt.Println("非常规内网ip默认扫b段")
			fmt.Println("scan class b subnet from input ip\n")
			return
		}else if os.Args[1] == "all" {
			fmt.Println("全量常规内网扫描...")
			inIP,err := GetInternalIP()
			if err != nil{
				fmt.Println("in-ip: "+inIP)
				Hosts = cidrToalive(inIP)
				if Hosts != nil {
					ICMPRun(Hosts)
					ICMPRun(Hosts)
				}
			}
			Hosts = cidrToalive("192.168.1.1")
			if Hosts != nil {
				ICMPRun(Hosts)
				ICMPRun(Hosts)
			}
			Hosts = cidrToalive("172.16.1.1")
			if Hosts != nil {
				ICMPRun(Hosts)
				ICMPRun(Hosts)
			}
			Hosts = cidrToalive("10.1.1.1")
			if Hosts != nil {
				ICMPRun(Hosts)
				ICMPRun(Hosts)
			}
			Hosts = cidrToalive("192.168.1.1")
			if Hosts != nil {
				ICMPRun(Hosts)
			}
			Hosts = cidrToalive("172.16.1.1")
			if Hosts != nil {
				ICMPRun(Hosts)
			}
			Hosts = cidrToalive("10.1.1.1")
			if Hosts != nil {
				ICMPRun(Hosts)
			}
		}else{
			Hosts = cidrToalive(os.Args[1])
			if Hosts != nil {
				ICMPRun(Hosts)
				ICMPRun(Hosts)
				ICMPRun(Hosts)
			}
		}
	}else{
		intSlice := strings.Split(os.Args[0],"\\")
		fmt.Println(intSlice[len(intSlice)-1])
		fmt.Println("无参数则根据当前网段信息进行扫描")
		fmt.Println("Default Scan\n")

		fmt.Println(intSlice[len(intSlice)-1]+" all")
		fmt.Println("10.0.0.0-10.255.255.255; 172.16.0.0-172.31.255.255; 192.168.0.0-192.168.255.255\n")


		fmt.Println(intSlice[len(intSlice)-1]+" 211.111.1.1")
		fmt.Println("非常规内网ip默认扫b段")
		fmt.Println("scan class b subnet from input ip\n")

		return
	}
}
