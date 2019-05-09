package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"strings"
	"net"
	"os"
	"path/filepath"
//	"bufio"
	"time"
	"strconv"
)

var (
	downStreamDataSize [10]int
	upStreamDataSize   [10]int
	deviceName        = flag.String("i", "eth0", "network interface device name")
	filter		      = flag.String("f", "tcp", "filter")
	separate          = flag.String("s", "", "separate network to display")
	interval          = flag.Int("t", 10, "interval")
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
	
	

	
	//separate networks
	separateNet := strings.Split(*separate, " ")
	
	go monitor(separateNet[:]) 
	
	// capture
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// only ethernet
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer != nil &&  ipLayer != nil{
			ethernet := ethernetLayer.(*layers.Ethernet)
			ip := ipLayer.(*layers.IPv4)
			// des MAC is local mac then downStream, otherwise upStream
			if ethernet.DstMAC.String() == macAddr {
				for i, displayNet := range separateNet {
					if ipInCidr(ip.SrcIP.String(),displayNet) {
						downStreamDataSize[i] += len(packet.Data())*8
					}
				}
			} else {
				for i, displayNet := range separateNet {
					if ipInCidr(ip.DstIP.String(),displayNet) {
						upStreamDataSize[i] += len(packet.Data())*8
					}
				}			
			}
		}
	}
}

func ipInCidr(ip, cidr string) bool {
    ipAddr := strings.Split(ip, `.`)
    if len(ipAddr) < 4 {
        return false
    }
    cidrArr := strings.Split(cidr, `/`)
    if len(cidrArr) < 2 {
        return false
    }
    var tmp = make([]string, 0)
    for key, value := range strings.Split(`255.255.255.0`, `.`) {
        iint, _ := strconv.Atoi(value)

        iint2, _ := strconv.Atoi(ipAddr[key])

        tmp = append(tmp, strconv.Itoa(iint&iint2))
    }
    return strings.Join(tmp, `.`) == cidrArr[0]
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

func PathExists(path string) (bool, error) {
    _, err := os.Stat(path)
    if err == nil {
        return true, nil
    }
    if os.IsNotExist(err) {
        return false, nil
    }
    return false, err
}

func monitor(separateNet []string) string {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}
	logdir := fmt.Sprintf("%s/log",dir)
	exist, err := PathExists(logdir)
	if err != nil {
		fmt.Printf("get dir error![%v]\n", err)
    }
	if !exist {
		err := os.Mkdir(logdir, os.ModePerm)
		if err != nil {
            fmt.Printf("mkdir failed![%v]\n", err)
        }
	}
	for {
		for i, displayNet := range separateNet {
		logFile := strings.Split(displayNet,"/")
		logFilename := logFile[0]+"_"+logFile[1]
		logPath := fmt.Sprintf("%s/%s.txt",logdir,logFilename)
		outputFile, outputError := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE, 0666)
		if outputError != nil {
			fmt.Printf("An error occurred with file opening or creation %s\n",logPath)
		}
		defer outputFile.Close()
		//outputWriter := bufio.NewWriter(outputFile)
		outputFile.WriteString(fmt.Sprintf("\r%s: Received:%d b/s Sent:%d b/s", displayNet, int(downStreamDataSize[i]/(*interval)), int(upStreamDataSize[i]/(*interval))))
		downStreamDataSize[i] = 0
		upStreamDataSize[i] = 0
		}
		time.Sleep(time.Duration(int(*interval)) * time.Second)
	}
}
