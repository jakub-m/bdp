package main

import (
	"jakub-m/bdp/flow"
	"jakub-m/bdp/frames"
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

	frames, err := frames.LoadFromFile(file)
	if err != nil {
		log.Fatal(err)
	}
	err = flow.ProcessFrames(frames)
	if err != nil {
		log.Fatal(err)
	}
}
