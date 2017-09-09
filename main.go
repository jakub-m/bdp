package main

import (
	"flag"
	"fmt"
	"jakub-m/bdp/flow"
	"jakub-m/bdp/packet"
	"jakub-m/bdp/pcap"
	"jakub-m/bdp/stats"
	"log"
	"os"
)

var args struct {
	pcapFname string
	localIP   *pcap.IPv4
	remoteIP  *pcap.IPv4
	statsMode bool
}

func init() {
	var localIPString string
	var remoteIPString string
	flag.StringVar(&args.pcapFname, "i", "", "pcap file")
	flag.StringVar(&localIPString, "l", "", "local IP (e.g. 192.168.1.2)")
	flag.StringVar(&remoteIPString, "r", "", "remote IP (e.g. 123.123.123.123)")
	flag.BoolVar(&args.statsMode, "s", false, "Print rudimentary flow statistics")
	flag.Parse()

	args.localIP = ipFromStringOrExit(localIPString)
	args.remoteIP = ipFromStringOrExit(remoteIPString)
}

func ipFromStringOrExit(ipString string) *pcap.IPv4 {
	if ipString == "" {
		return nil
	}

	ip, err := pcap.IPv4FromString(ipString)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return &ip
}

func main() {
	log.SetFlags(0)
	log.Println("Pcap file name: ", args.pcapFname)
	log.Println("Local IP: ", args.localIP)
	log.Println("Remote IP: ", args.remoteIP)
	file, err := os.Open(args.pcapFname)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	onPcapError := func(err error) bool {
		log.Printf("Packet reading error: %s", err)
		return true
	}

	// Load all the packets to memory. It can be easily converted to streaming.
	packets, err := packet.LoadFromFile(file, onPcapError)
	if err != nil {
		log.Fatal(err)
	}

	if args.statsMode {
		// Stats mode.
		stats.ProcessPackets(packets)
	} else {
		// BDP mode.
		err = flow.ProcessPackets(packets, args.localIP, args.remoteIP)
		if err != nil {
			log.Fatal(err)
		}
	}
}
