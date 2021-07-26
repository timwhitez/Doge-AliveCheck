package main

import (
	"bytes"
	"errors"
	"fmt"
	"golang.org/x/net/icmp"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	AliveHosts []string
	OS         = runtime.GOOS
	ExistHosts = make(map[string]struct{})
	livewg     sync.WaitGroup

	)


func IsContain(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func ICMPRun(hostslist []string) []string {
	chanHosts := make(chan string, len(hostslist))
	go func() {
		for ip := range chanHosts {
			if _, ok := ExistHosts[ip]; !ok && IsContain(hostslist, ip) {
				ExistHosts[ip] = struct{}{}
				ip1 := strings.Split(ip,".")[0]
				ip2 := strings.Split(ip,".")[1]
				ip3 := strings.Split(ip,".")[2]
				cidr := ip1+"."+ip2+"."+ip3+".1/24"
				if !stringInSlice(cidr,AliveHosts){
					fmt.Println(cidr)
				}
				AliveHosts = append(AliveHosts, cidr)
			}
			livewg.Done()
		}
	}()

	//优先尝试监听本地icmp,批量探测
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err == nil {
		RunIcmp1(hostslist, conn, chanHosts)
	} else {
		//尝试无监听icmp探测
		conn, err := net.DialTimeout("ip4:icmp", "127.0.0.1", 3*time.Second)
		if err == nil {
			go conn.Close()
			RunIcmp2(hostslist, chanHosts)
		} else {
			//使用ping探测
			fmt.Println("The current user permissions unable to send icmp packets")
			fmt.Println("start ping")
			RunPing(hostslist, chanHosts)
		}
	}


	livewg.Wait()
	close(chanHosts)
	return AliveHosts
}

func RunIcmp1(hostslist []string, conn *icmp.PacketConn, chanHosts chan string) {
	endflag := false
	go func() {
		for {
			if endflag == true {
				return
			}
			msg := make([]byte, 100)
			_, sourceIP, _ := conn.ReadFrom(msg)
			if sourceIP != nil {
				livewg.Add(1)
				chanHosts <- sourceIP.String()
			}
		}
	}()

	for _, host := range hostslist {
		dst, _ := net.ResolveIPAddr("ip", host)
		IcmpByte := makemsg(host)
		conn.WriteTo(IcmpByte, dst)
	}
	//根据hosts数量修改icmp监听时间
	start := time.Now()
	for {
		if len(AliveHosts) == len(hostslist) {
			break
		}
		since := time.Now().Sub(start)
		var wait time.Duration
		switch {
		case len(hostslist) <= 256:
			wait = time.Second * 3
		default:
			wait = time.Second * 6
		}
		if since > wait {
			break
		}
	}
	endflag = true
	conn.Close()
}

func RunIcmp2(hostslist []string, chanHosts chan string) {
	num := 1000
	if len(hostslist) < num {
		num = len(hostslist)
	}
	var wg sync.WaitGroup
	limiter := make(chan struct{}, num)
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			if icmpalive(host) {
				livewg.Add(1)
				chanHosts <- host
			}
			<-limiter
			wg.Done()
		}(host)
	}
	wg.Wait()
	close(limiter)
}

func icmpalive(host string) bool {
	startTime := time.Now()
	conn, err := net.DialTimeout("ip4:icmp", host, 6*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	if err := conn.SetDeadline(startTime.Add(6 * time.Second)); err != nil {
		return false
	}
	msg := makemsg(host)
	if _, err := conn.Write(msg); err != nil {
		return false
	}

	receive := make([]byte, 60)
	if _, err := conn.Read(receive); err != nil {
		return false
	}

	return true
}

func RunPing(hostslist []string, chanHosts chan string) {
	var bsenv = ""
	if OS != "windows" {
		bsenv = "/bin/bash"
	}
	var wg sync.WaitGroup
	limiter := make(chan struct{}, 50)
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			if ExecCommandPing(host, bsenv) {
				livewg.Add(1)
				chanHosts <- host
			}
			<-limiter
			wg.Done()
		}(host)
	}
	wg.Wait()
}

func ExecCommandPing(ip string, bsenv string) bool {
	var command *exec.Cmd
	if OS == "windows" {
		command = exec.Command("cmd", "/c", "ping -n 1 -w 1 "+ip+" && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	} else if OS == "linux" {
		command = exec.Command(bsenv, "-c", "ping -c 1 -w 1 "+ip+" >/dev/null && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	} else if OS == "darwin" {
		command = exec.Command(bsenv, "-c", "ping -c 1 -W 1 "+ip+" >/dev/null && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	}
	outinfo := bytes.Buffer{}
	command.Stdout = &outinfo
	err := command.Start()
	if err != nil {
		return false
	}
	if err = command.Wait(); err != nil {
		return false
	} else {
		if strings.Contains(outinfo.String(), "true") {
			return true
		} else {
			return false
		}
	}
}

func makemsg(host string) []byte {
	msg := make([]byte, 40)
	id0, id1 := genIdentifier(host)
	msg[0] = 8
	msg[1] = 0
	msg[2] = 0
	msg[3] = 0
	msg[4], msg[5] = id0, id1
	msg[6], msg[7] = genSequence(1)
	check := checkSum(msg[0:40])
	msg[2] = byte(check >> 8)
	msg[3] = byte(check & 255)
	return msg
}

func checkSum(msg []byte) uint16 {
	sum := 0
	length := len(msg)
	for i := 0; i < length-1; i += 2 {
		sum += int(msg[i])*256 + int(msg[i+1])
	}
	if length%2 == 1 {
		sum += int(msg[length-1]) * 256
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	answer := uint16(^sum)
	return answer
}

func genSequence(v int16) (byte, byte) {
	ret1 := byte(v >> 8)
	ret2 := byte(v & 255)
	return ret1, ret2
}

func genIdentifier(host string) (byte, byte) {
	return host[0], host[1]
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
