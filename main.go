package main

import (
	"jakub-m/bdp/flow"
	"jakub-m/bdp/packet"
	"log"
	"os"
)

func main() {
	pcapFileName := os.Args[1]
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
