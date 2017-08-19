package main

import (
	"fmt"
	"io"
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

	err = frames.ProcessFrames(file, printFrame)
	if err != nil && err != io.EOF {
		log.Fatal(err)
	}
}

func printFrame(f *frames.Frame) error {
	fmt.Println(f.Record.String())
	fmt.Println(f.Ether.String())
	fmt.Println(f.IP.String())
	fmt.Println(f.TCP.String())
	return nil
}
