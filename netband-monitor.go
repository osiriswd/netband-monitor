package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"os"
	"time"
)

var (
	downStreamDataSize = 0
	upStreamDataSize   = 0
	deviceName        = flag.String("i", "eth0", "network interface device name")
	filter		      = flag.String("f", "tcp", "filter")
    snapshotLen int32  = 1024
    promiscuous bool   = false
    timeout     time.Duration = 30 * time.Second
    handle      *pcap.Handle
)

func main() {
	flag.Parse()

	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Find exact device
	var device pcap.Interface
	for _, d := range devices {
		if d.Name == *deviceName {
			device = d
		}
	}

	
	// get mac
	macAddr, err := findMacAddrByIp(findDeviceIpv4(device))
	if err != nil {
		panic(err)
	}

	fmt.Printf("Chosen device's IPv4: %s\n", findDeviceIpv4(device))
	fmt.Printf("Chosen device's MAC: %s\n", macAddr)
	fmt.Printf("Filter: %s\n", *filter)

	// handler
	handle, err := pcap.OpenLive(*deviceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	// Set filter
    err = handle.SetBPFFilter(*filter)
    if err != nil {
        log.Fatal(err)
    }
	
	
	go monitor() 
	
	// capture
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// only ethernet
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer != nil {
			ethernet := ethernetLayer.(*layers.Ethernet)
			// des MAC is local mac then downStream, otherwise upStream
			if ethernet.DstMAC.String() == macAddr {
				downStreamDataSize += len(packet.Data())*8
			} else {
				upStreamDataSize += len(packet.Data())*8
			}
		}
	}
}

func findDeviceIpv4(device pcap.Interface) string {
	for _, addr := range device.Addresses {
		if ipv4 := addr.IP.To4(); ipv4 != nil {
			return ipv4.String()
		}
	}
	panic("device has no IPv4")
}

// IPv4 to get MAC
func findMacAddrByIp(ip string) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		panic(interfaces)
	}

	for _, i := range interfaces {
		addrs, err := i.Addrs()
		if err != nil {
			panic(err)
		}

		for _, addr := range addrs {
			if a, ok := addr.(*net.IPNet); ok {
				if ip == a.IP.String() {
					return i.HardwareAddr.String(), nil
				}
			}
		}
	}
	return "", errors.New(fmt.Sprintf("no device has given ip: %s", ip))
}

func monitor() {
	for {
		os.Stdout.WriteString(fmt.Sprintf("\rReceived:%.2fkb/s \t Sent:%.2fkb/s", float32(downStreamDataSize)/1024/1, float32(upStreamDataSize)/1024/1))
		downStreamDataSize = 0
		upStreamDataSize = 0
		time.Sleep(1 * time.Second)
	}
}
