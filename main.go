package main

import (
	"flag"
	"jakub-m/bdp/flow"
	"jakub-m/bdp/packet"
	"log"
	"os"
)

var args struct {
	pcapFname string
}

func init() {
	flag.StringVar(&args.pcapFname, "i", "", "pcap file")
	flag.Parse()
}

func main() {
	pcapFileName := args.pcapFname
	log.SetFlags(0)
	log.Println("Pcap file name: ", pcapFileName)
	file, err := os.Open(pcapFileName)
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
