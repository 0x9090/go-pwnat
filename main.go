package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway"
	"github.com/robfig/cron/v3"
	"golang.org/x/net/icmp"
	"math/rand"
	"net"
	"runtime"
	"strings"
	"time"
)

func main() {
	PwnnatServer()
	playPayload := []byte{0x1, 0x2, 0x3}
	PwnnatClient(net.ParseIP("127.0.0.1"), playPayload)
}

func getOutboundIP() net.IP {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		panic(err)
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			panic(err)
		}
	}(conn)
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

func getInterface() (device string, mac *net.HardwareAddr, gwip *net.IP, src *net.IP, err error) {
	newGwip, err := gateway.DiscoverGateway()
	if err != nil {
		panic(err)
	}
	device, myIP := selectDevice()
	newMac := getMAC(myIP)
	return device, &newMac, &newGwip, &myIP, nil
}

func getMAC(ip net.IP) net.HardwareAddr {
	interfaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	for _, interf := range interfaces {
		if addrs, err := interf.Addrs(); err == nil {
			for _, addr := range addrs {
				if strings.Split(addr.String(), "/")[0] == ip.String() {
					return interf.HardwareAddr
				}
			}
		}
	}
	return net.HardwareAddr{0, 0, 0, 0, 0, 0}
}

func selectDevice() (device string, ip net.IP) {
	// https://gist.github.com/FlameInTheDark/b1957b95a89493ec6ce346bad156dc61#file-main-go
	localIP := getOutboundIP()
	devices, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}
	var name string
	for _, device := range devices {
		for _, address := range device.Addresses {
			if localIP != nil {
				if address.IP.String() == localIP.String() {
					name = device.Name
				}
			} else if address.IP.String() != "127.0.0.1" && !strings.Contains(device.Description, "Loopback") {
				name = device.Name
			}
		}
	}
	return name, localIP
}

func PwnnatServer() {
	// samy.pl/pwnat/
	icmpServerEcho()
	crontab := cron.New(cron.WithSeconds())
	_, err := crontab.AddFunc("@every 30s", icmpServerEcho)
	if err != nil {
		panic("Could not start pwnnat server requests")
	}
	crontab.Start()
	serverListener()
}

func constructICMP(dstIP net.IP, ttl uint8, icmpType uint8, data []byte) []byte {
	eth := &layers.Ethernet{}
	eth.EthernetType = layers.EthernetTypeIPv4
	eth.SrcMAC = getMAC(getOutboundIP())
	eth.DstMAC = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	ip := &layers.IPv4{}
	ip.Version = 4
	ip.Protocol = layers.IPProtocolICMPv4
	ip.Flags = layers.IPv4DontFragment
	ip.SrcIP = getOutboundIP()
	ip.DstIP = dstIP
	ip.TTL = ttl

	icmp := &layers.ICMPv4{}
	icmp.TypeCode = layers.CreateICMPv4TypeCode(icmpType, 0) // 0x0800
	icmp.Id = uint16(rand.Uint32())
	icmp.Seq = 1
	icmp.Checksum = 0

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, opts, eth, ip, icmp, gopacket.Payload(data))
	if err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func sendPacket(packet []byte) {
	timeout := 30 * time.Second
	device, _, _, _, _ := getInterface()
	handle, err := pcap.OpenLive(device, 1024, false, timeout)
	if err != nil {
		panic(err)
	}
	defer handle.Close()
	err = handle.WritePacketData(packet)
	if err != nil {
		panic(err)
	}
}

func icmpServerEcho() {
	// https://github.com/margina757/probe/blob/32336a0fd7b1013825362767f4a22689ec183a93/probe/ping.go
	// https://github.com/wangzhezhe/gopacketlearn/blob/master/createpacket.go
	payload := []byte{0x70, 0x65, 0x65, 0x70, 0x65, 0x65, 0x70, 0x6f, 0x6f, 0x70, 0x6f, 0x6f}
	echoPacket := constructICMP(net.ParseIP("1.2.3.4"), 3, layers.ICMPv4TypeEchoRequest, payload)
	sendPacket(echoPacket)
}

func serverListener() {
	// https://stackoverflow.com/questions/2937123/implementing-icmp-ping-in-go
	fmt.Println("starting listener")
	if runtime.GOOS == "windows" {
		fmt.Println("Can't perform pwnnat on Windows yet due to a Golang bug. See code comments for more.")
		return
	}
	listener, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	// ^^^ broken on Windows :(  https://github.com/golang/go/issues/38427
	// I can use other packet types to accomplish this cross-platform, but ugh the extra work #TODO
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	packetsChannel := make(chan *icmp.Echo)
	for {
		go func() {
			buff := make([]byte, 1500)
			size, _, err := listener.ReadFrom(buff)
			if err != nil {
				panic(err)
			}
			message, err := icmp.ParseMessage(58, buff[:size])
			if err != nil {
				panic(err)
			}
			body := message.Body.(*icmp.Echo)
			packetsChannel <- body
		}()
	}
}

func PwnnatClient(serverIP net.IP, tunneledPayload []byte) {
	childPacket := constructICMP(net.ParseIP("1.2.3.4"), 128, layers.ICMPv4TypeEchoRequest, tunneledPayload)
	parentPacket := constructICMP(serverIP, 128, layers.ICMPv4TypeTimeExceeded, childPacket)
	fmt.Println("send it..")
	sendPacket(parentPacket)
}
