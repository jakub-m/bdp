package flow

import (
	"fmt"
	"jakub-m/bdp/packet"
	"jakub-m/bdp/pcap"
)

func ProcessPackets(packets []*packet.Packet) error {
	flow := &flow{}

	for _, f := range packets {
		flow.consumePacket(f)
		msg := flow.fmtPacket(f)
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
	inflight      []*packet.Packet
}

// initSeqNum is initial sequence number.
type flowDetails struct {
	ip         pcap.IPv4
	port       uint16
	initSeqNum pcap.SeqNum
}

func (f *flow) consumePacket(packet *packet.Packet) {
	if packet.TCP.IsSyn() && !packet.TCP.IsAck() {
		f.onSyn(packet)
	} else if packet.TCP.IsSyn() && packet.TCP.IsAck() {
		f.onSynAck(packet)
	} else if f.isLocalToRemote(packet) {
		f.onSend(packet)
	} else if f.isRemoteToLocal(packet) && packet.TCP.IsAck() {
		f.onAck(packet)
	}
}

func (f *flow) onSyn(packet *packet.Packet) {
	f.local.ip = packet.IP.SourceIP()
	f.local.port = packet.TCP.SourcePort()
	f.local.initSeqNum = packet.TCP.SeqNum()
	f.remote.ip = packet.IP.DestIP()
	f.remote.port = packet.TCP.DestPort()
	f.initTimestamp = packet.Record.Timestamp()
}

func (f *flow) onSynAck(packet *packet.Packet) {
	f.remote.initSeqNum = packet.TCP.SeqNum()
}

// Packets sent are inflight until acknowledged. Only packets with payload are expected to be acknowledged (i.e. pure 'acks' with no payload do not count as inflight.)
func (f *flow) onSend(packet *packet.Packet) {
	payloadSize := packet.PayloadSize()
	if payloadSize == 0 {
		return
	}
	f.inflight = append(f.inflight, packet)
	fmt.Print("inflight ", len(f.inflight))
	for _, g := range f.inflight {
		fmt.Print(" ", f.getExpectedSeqNum(g))
	}
	fmt.Println()
}

func (f *flow) onAck(packet *packet.Packet) {
	ackNum := packet.TCP.AckNum().RelativeTo(f.local.initSeqNum)
	for i, g := range f.inflight {
		// Consider adding "flowPacket" wrapping packet and flow-related information (is local, expected seq num).
		expSeqNum := f.getExpectedSeqNum(g)
		if ackNum == expSeqNum {
			f.inflight = f.inflight[i+1:]
			// what if there are many packets acknowledged?
			fmt.Println("got ack match: ", i, ackNum, "rtt:", packet.Record.Timestamp()-g.Record.Timestamp(), "us")
		}
	}
}

func (f *flow) getExpectedSeqNum(packet *packet.Packet) uint32 {
	payloadSize := uint32(packet.PayloadSize())
	if f.isLocalToRemote(packet) {
		// FIXME: handle next syn at integer boundaries gracefully.
		relSyn := packet.TCP.SeqNum().RelativeTo(f.local.initSeqNum)
		return relSyn + payloadSize
	}
	if f.isRemoteToLocal(packet) {
		relSyn := packet.TCP.SeqNum().RelativeTo(f.remote.initSeqNum)
		return relSyn + payloadSize
	}
	// This should never happen since all the packets for a flow should be either local-to-remote or remote-to-local.
	panic(fmt.Sprintf("getExpectedSeqNum invoked for packet that does not belong to the flow. flow: %v, packet: %v", f, packet))
}

func (f *flow) fmtPacket(packet *packet.Packet) string {
	msg := fmt.Sprintf("%d", packet.Record.Timestamp()-f.initTimestamp)
	msg += fmt.Sprintf(" %s %d -> %s %d", packet.IP.SourceIP(), packet.TCP.SourcePort(), packet.IP.DestIP(), packet.TCP.DestPort())
	if packet.TCP.IsSyn() {
		msg += " syn"
	}
	if packet.TCP.IsAck() {
		msg += " ack"
	}
	payloadSize := uint32(packet.PayloadSize())
	if f.isLocalToRemote(packet) {
		relSyn := packet.TCP.SeqNum().RelativeTo(f.local.initSeqNum)
		relAck := packet.TCP.AckNum().RelativeTo(f.remote.initSeqNum)
		// FIXME: handle next syn at integer boundaries gracefully.
		nextSyn := relSyn + payloadSize
		msg += fmt.Sprintf(" >  %d. seq %d (exp %d) ack %d", payloadSize, relSyn, nextSyn, relAck)
	}
	if f.isRemoteToLocal(packet) {
		relSyn := packet.TCP.SeqNum().RelativeTo(f.remote.initSeqNum)
		relAck := packet.TCP.AckNum().RelativeTo(f.local.initSeqNum)
		nextSyn := relSyn + payloadSize
		msg += fmt.Sprintf("  < %d. seq %d (exp %d) ack %d", payloadSize, relSyn, nextSyn, relAck)
	}
	return msg
}

// isLocalToRemote indicates if a packet represents a packet going from local to remote.
func (f *flow) isLocalToRemote(packet *packet.Packet) bool {
	return f.local.ip == packet.IP.SourceIP() &&
		f.local.port == packet.TCP.SourcePort() &&
		f.remote.ip == packet.IP.DestIP() &&
		f.remote.port == packet.TCP.DestPort()
}

// isRemoteToLocal indicates if a packet represents a packet going from remote to local.
func (f *flow) isRemoteToLocal(packet *packet.Packet) bool {
	return f.remote.ip == packet.IP.SourceIP() &&
		f.remote.port == packet.TCP.SourcePort() &&
		f.local.ip == packet.IP.DestIP() &&
		f.local.port == packet.TCP.DestPort()
}
