package main

import (
	"fmt"
	"jakub-m/bdp/pcap"
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
	p, err := pcap.NewPcap(file)
	if err != nil {
		log.Fatal(err)
	}

	for {
		record, err := p.NextRecord()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(record.String())
		eth, err := pcap.ParseEtherFrame(record.Data)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(eth.String())
	}
}
