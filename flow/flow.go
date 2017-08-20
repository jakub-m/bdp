package flow

import (
	"fmt"
	"jakub-m/bdp/frames"
	"jakub-m/bdp/pcap"
)

func ProcessFrames(frames []*frames.Frame) error {
	flow := &flow{}

	for _, f := range frames {
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

		msg := flow.fmtFrame(f)
		fmt.Println(msg)
	}
	return nil
}

// initTimestamp initial timestamp in microseconds
// local is the side that initiates connection (syn).
// remote is the other side of the connection (syn ack).
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

func (f *flow) fmtFrame(frame *frames.Frame) string {
	msg := fmt.Sprintf("%d", frame.Record.Timestamp()-f.initTimestamp)
	msg += fmt.Sprintf(" %s %d -> %s %d", frame.IP.SourceIP(), frame.TCP.SourcePort(), frame.IP.DestIP(), frame.TCP.DestPort())
	if frame.TCP.IsSyn() {
		msg += " syn"
	}
	if frame.TCP.IsAck() {
		msg += " ack"
	}
	payloadSize := uint32(frame.PayloadSize())
	if f.isLocalToRemote(frame) {
		relSyn := frame.TCP.SeqNum().RelativeTo(f.local.initSeqNum)
		relAck := frame.TCP.AckNum().RelativeTo(f.remote.initSeqNum)
		// FIXME: handle next syn at integer boundaries gracefully.
		nextSyn := relSyn + payloadSize
		msg += fmt.Sprintf(" >  %d. seq %d (exp %d) ack %d", payloadSize, relSyn, nextSyn, relAck)
	}
	if f.isRemoteToLocal(frame) {
		relSyn := frame.TCP.SeqNum().RelativeTo(f.remote.initSeqNum)
		relAck := frame.TCP.AckNum().RelativeTo(f.local.initSeqNum)
		nextSyn := relSyn + payloadSize
		msg += fmt.Sprintf("  < %d. seq %d (exp %d) ack %d", payloadSize, relSyn, nextSyn, relAck)
	}
	return msg
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
