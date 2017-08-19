package main

import (
	"fmt"
	"io"
	"jakub-m/bdp/frames"
	"jakub-m/bdp/pcap"
	"log"
	"os"
)

// initTimestamp initial timestamp in microseconds
// local is the side that initiates connection (syn).
// rmeote is the other side of the connection (syn ack).
type flow struct {
	initTimestamp uint64
	local         flowDetails
	remote        flowDetails
}

// initSeqNum is initial sequence number.
type flowDetails struct {
	ip         pcap.IPv4
	port       uint16
	initSeqNum pcap.SeqNum
}

// isLocalToRemote indicates if a frame represents a packet going from local to remote.
func (f *flow) isLocalToRemote(frame *frames.Frame) bool {
	return f.local.ip == frame.IP.SourceIP() &&
		f.local.port == frame.TCP.SourcePort() &&
		f.remote.ip == frame.IP.DestIP() &&
		f.remote.port == frame.TCP.DestPort()
}

// isRemoteToLocal indicates if a frame represents a packet going from remote to local.
func (f *flow) isRemoteToLocal(frame *frames.Frame) bool {
	return f.remote.ip == frame.IP.SourceIP() &&
		f.remote.port == frame.TCP.SourcePort() &&
		f.local.ip == frame.IP.DestIP() &&
		f.local.port == frame.TCP.DestPort()
}

func main() {
	pcapFileName := os.Args[1]
	log.Println("Pcap file name: ", pcapFileName)
	file, err := os.Open(pcapFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	flow := &flow{}

	printFrame := func(f *frames.Frame) error {
		if f.TCP.IsSyn() && !f.TCP.IsAck() { // syn
			flow.local.ip = f.IP.SourceIP()
			flow.local.port = f.TCP.SourcePort()
			flow.local.initSeqNum = f.TCP.SeqNum()
			flow.remote.ip = f.IP.DestIP()
			flow.remote.port = f.TCP.DestPort()
			flow.initTimestamp = f.Record.Timestamp()
		}

		if f.TCP.IsSyn() && f.TCP.IsAck() { // syn ack
			flow.remote.initSeqNum = f.TCP.SeqNum()
		}

		msg := fmt.Sprintf("%d", f.Record.Timestamp()-flow.initTimestamp)
		msg += fmt.Sprintf(" %s %d -> %s %d", f.IP.SourceIP(), f.TCP.SourcePort(), f.IP.DestIP(), f.TCP.DestPort())
		if f.TCP.IsSyn() {
			msg += " syn"
		}
		if f.TCP.IsAck() {
			msg += " ack"
		}
		if flow.isLocalToRemote(f) {
			msg += fmt.Sprintf(" >  seq %d ack %d", f.TCP.SeqNum().RelativeTo(flow.local.initSeqNum), f.TCP.AckNum().RelativeTo(flow.remote.initSeqNum))
		}
		if flow.isRemoteToLocal(f) {
			msg += fmt.Sprintf(" << seq %d ack %d", f.TCP.SeqNum().RelativeTo(flow.remote.initSeqNum), f.TCP.AckNum().RelativeTo(flow.local.initSeqNum))
		}

		fmt.Println(msg)
		return nil
	}

	err = frames.ProcessFrames(file, printFrame)
	if err != nil && err != io.EOF {
		log.Fatal(err)
	}
}
