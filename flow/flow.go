package flow

import (
	"fmt"
	"jakub-m/bdp/frames"
	"jakub-m/bdp/pcap"
)

func ProcessFrames(frames []*frames.Frame) error {
	flow := &flow{}

	for _, f := range frames {
		flow.consumeFrame(f)
		msg := flow.fmtFrame(f)
		fmt.Println(msg)
	}
	return nil
}

// initTimestamp initial timestamp in microseconds
// local is the side that initiates connection (syn).
// remote is the other side of the connection (syn ack).
// inflight are the files that are sent from local to remote and are not yet acknowledged.
type flow struct {
	initTimestamp uint64
	local         flowDetails
	remote        flowDetails
	inflight      []*frames.Frame
}

// initSeqNum is initial sequence number.
type flowDetails struct {
	ip         pcap.IPv4
	port       uint16
	initSeqNum pcap.SeqNum
}

func (f *flow) consumeFrame(frame *frames.Frame) {
	if frame.TCP.IsSyn() && !frame.TCP.IsAck() {
		f.onSyn(frame)
	} else if frame.TCP.IsSyn() && frame.TCP.IsAck() {
		f.onSynAck(frame)
	} else if f.isLocalToRemote(frame) {
		f.onSend(frame)
	} else if f.isRemoteToLocal(frame) && frame.TCP.IsAck() {
		f.onAck(frame)
	}
}

func (f *flow) onSyn(frame *frames.Frame) {
	f.local.ip = frame.IP.SourceIP()
	f.local.port = frame.TCP.SourcePort()
	f.local.initSeqNum = frame.TCP.SeqNum()
	f.remote.ip = frame.IP.DestIP()
	f.remote.port = frame.TCP.DestPort()
	f.initTimestamp = frame.Record.Timestamp()
}

func (f *flow) onSynAck(frame *frames.Frame) {
	f.remote.initSeqNum = frame.TCP.SeqNum()
}

// Packets sent are inflight until acknowledged. Only packets with payload are expected to be acknowledged (i.e. pure 'acks' with no payload do not count as inflight.)
func (f *flow) onSend(frame *frames.Frame) {
	payloadSize := frame.PayloadSize()
	if payloadSize == 0 {
		return
	}
	f.inflight = append(f.inflight, frame)
	fmt.Print("inflight ", len(f.inflight))
	for _, g := range f.inflight {
		fmt.Print(" ", f.getExpectedSeqNum(g))
	}
	fmt.Println()
}

func (f *flow) onAck(frame *frames.Frame) {
	ackNum := frame.TCP.AckNum().RelativeTo(f.local.initSeqNum)
	for i, g := range f.inflight {
		// Consider adding "flowFrame" wrapping frame and flow-related information (is local, expected seq num).
		expSeqNum := f.getExpectedSeqNum(g)
		if ackNum == expSeqNum {
			f.inflight = f.inflight[i+1:]
			// what if there are many packets acknowledged?
			fmt.Println("got ack match: ", i, ackNum, "rtt:", frame.Record.Timestamp()-g.Record.Timestamp(), "us")
		}
	}
}

func (f *flow) getExpectedSeqNum(frame *frames.Frame) uint32 {
	payloadSize := uint32(frame.PayloadSize())
	if f.isLocalToRemote(frame) {
		// FIXME: handle next syn at integer boundaries gracefully.
		relSyn := frame.TCP.SeqNum().RelativeTo(f.local.initSeqNum)
		return relSyn + payloadSize
	}
	if f.isRemoteToLocal(frame) {
		relSyn := frame.TCP.SeqNum().RelativeTo(f.remote.initSeqNum)
		return relSyn + payloadSize
	}
	// This should never happen since all the frames for a flow should be either local-to-remote or remote-to-local.
	panic(fmt.Sprintf("getExpectedSeqNum invoked for frame that does not belong to the flow. flow: %v, frame: %v", f, frame))
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
