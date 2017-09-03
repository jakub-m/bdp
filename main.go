package main

import (
	"flag"
	"fmt"
	"jakub-m/bdp/flow"
	"jakub-m/bdp/packet"
	"jakub-m/bdp/pcap"
	"log"
	"os"
)

var args struct {
	pcapFname string
	localIP   *pcap.IPv4
}

func init() {
	var localIpString string
	flag.StringVar(&args.pcapFname, "i", "", "pcap file")
	flag.StringVar(&localIpString, "l", "", "local IP (e.g. 192.168.1.2)")
	flag.Parse()

	if localIpString != "" {
		ip, err := pcap.IPv4FromString(localIpString)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		args.localIP = &ip
	}
}

func main() {
	log.SetFlags(0)
	log.Println("Pcap file name: ", args.pcapFname)
	log.Println("Local IP: ", args.localIP)
	file, err := os.Open(args.pcapFname)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	packets, err := packet.LoadFromFile(file)
	if err != nil {
		log.Fatal(err)
	}

	err = flow.ProcessPackets(packets)
	if err != nil {
		log.Fatal(err)
	}
}
