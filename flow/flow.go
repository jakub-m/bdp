package flow

import (
	"fmt"
	"jakub-m/bdp/packet"
	"jakub-m/bdp/pcap"
)

func ProcessPackets(packets []*packet.Packet) error {
	flow := &flow{
		gotSyn:    false,
		gotSynAck: false,
	}

	for _, f := range packets {
		fp := flow.consumePacket(f)
		fmt.Println(fp.String())
	}
	return nil
}

// initTimestamp initial timestamp in microseconds
// local is the side that initiates connection (syn).
// remote is the other side of the connection (syn ack).
// inflight are the files that are sent from local to remote and are not yet acknowledged.
type flow struct {
	initTimestamp uint64
	gotSyn        bool
	gotSynAck     bool
	local         flowDetails
	remote        flowDetails
	inflight      []*flowPacket
}

func (f *flow) consumePacket(packet *packet.Packet) *flowPacket {
	// TODO: Handle flows without syn and syn+ack, and out-of-order.
	if packet.TCP.IsSyn() && !packet.TCP.IsAck() {
		flowPacket := f.createSynFlowPacket(packet)
		f.onSyn(flowPacket)
		return flowPacket
	} else if packet.TCP.IsSyn() && packet.TCP.IsAck() {
		flowPacket := f.createSynAckFlowPacket(packet)
		f.onSynAck(flowPacket)
		return flowPacket
	} else {
		flowPacket := f.createFlowPacket(packet)
		if flowPacket.direction == localToRemote {
			f.onSend(flowPacket)
		} else if flowPacket.direction == remoteToLocal && flowPacket.packet.TCP.IsAck() {
			f.onAck(flowPacket)
		} else {
			panic("direction not set!")
		}
		return flowPacket
	}
}

func (f *flow) onSyn(p *flowPacket) {
	f.local.ip = p.packet.IP.SourceIP()
	f.local.port = p.packet.TCP.SourcePort()
	f.local.initSeqNum = p.packet.TCP.SeqNum()
	f.remote.ip = p.packet.IP.DestIP()
	f.remote.port = p.packet.TCP.DestPort()
	f.initTimestamp = p.packet.Record.Timestamp()
	f.gotSyn = true
}

func (f *flow) onSynAck(p *flowPacket) {
	f.remote.initSeqNum = p.packet.TCP.SeqNum()
	f.gotSynAck = true
}

// Packets sent are inflight until acknowledged. Only packets with payload are expected to be acknowledged (i.e. pure 'acks' with no payload do not count as inflight.)
func (f *flow) onSend(p *flowPacket) {
	if p.packet.PayloadSize() == 0 {
		return
	}
	// Assert that packets are sorted by expectedAckNum.
	if len(f.inflight) > 0 {
		lastInflight := f.inflight[len(f.inflight)-1]
		if lastInflight.expectedAckNum >= p.expectedAckNum {
			panic(fmt.Sprintf("Wrong order of expectedAckNum. last inflight %s, current %s", lastInflight.String(), p.String()))
		}
	}
	f.inflight = append(f.inflight, p)
}

func (f *flow) onAck(p *flowPacket) {
	for i, g := range f.inflight {
		if p.relativeAckNum == g.expectedAckNum {
			// All inflight packets up to i are confirmed, so the ones before can be dropped.
			f.inflight = f.inflight[i+1:]
			fmt.Println("got ack match: ", i, p.relativeAckNum, "rtt:", p.packet.Record.Timestamp()-g.packet.Record.Timestamp(), "us")
		}
	}
}

func (f *flow) panicIfNotReady() {
	if !(f.gotSyn && f.gotSynAck) {
		panic("did not get syn nor syn+ack")
	}
}

func (f *flow) createSynFlowPacket(packet *packet.Packet) *flowPacket {
	return &flowPacket{
		packet:            packet,
		relativeTimestamp: f.getRelativeTimestamp(packet),
		direction:         localToRemote,
		relativeSeqNum:    0,
		relativeAckNum:    0,
		expectedAckNum:    1,
	}
}

func (f *flow) createSynAckFlowPacket(packet *packet.Packet) *flowPacket {
	return &flowPacket{
		packet:            packet,
		relativeTimestamp: f.getRelativeTimestamp(packet),
		direction:         remoteToLocal,
		relativeSeqNum:    0,
		relativeAckNum:    0,
		expectedAckNum:    1,
	}
}

func (f *flow) createFlowPacket(packet *packet.Packet) *flowPacket {
	f.panicIfNotReady()

	flowPacket := &flowPacket{
		packet:            packet,
		relativeTimestamp: f.getRelativeTimestamp(packet),
	}

	if f.isLocalToRemote(packet) {
		flowPacket.direction = localToRemote
		flowPacket.relativeSeqNum = packet.TCP.SeqNum().RelativeTo(f.local.initSeqNum)
		flowPacket.relativeAckNum = packet.TCP.AckNum().RelativeTo(f.remote.initSeqNum)
		// FIXME: handle next syn at integer boundaries gracefully.
		flowPacket.expectedAckNum = flowPacket.relativeSeqNum.ExpectedForPayload(packet.PayloadSize())
	} else if f.isRemoteToLocal(packet) {
		flowPacket.direction = remoteToLocal
		flowPacket.relativeSeqNum = packet.TCP.SeqNum().RelativeTo(f.remote.initSeqNum)
		flowPacket.relativeAckNum = packet.TCP.AckNum().RelativeTo(f.local.initSeqNum)
		flowPacket.expectedAckNum = flowPacket.relativeSeqNum.ExpectedForPayload(packet.PayloadSize())
	} else {
		panic("Unknown direction!")
	}

	return flowPacket
}

func (f *flow) getRelativeTimestamp(packet *packet.Packet) uint64 {
	return packet.Record.Timestamp() - f.initTimestamp
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

// initSeqNum is initial sequence number.
type flowDetails struct {
	ip         pcap.IPv4
	port       uint16
	initSeqNum pcap.SeqNum
}

// flowPacket is a packet.Packet with flow context
type flowPacket struct {
	relativeTimestamp uint64
	packet            *packet.Packet
	direction         flowPacketDirection
	relativeSeqNum    pcap.SeqNum
	relativeAckNum    pcap.SeqNum
	expectedAckNum    pcap.SeqNum
}

type flowPacketDirection int

const (
	localToRemote flowPacketDirection = iota
	remoteToLocal
)

func (p *flowPacket) String() string {
	msg := fmt.Sprintf("%d", p.relativeTimestamp)
	msg += fmt.Sprintf(" %s %d -> %s %d", p.packet.IP.SourceIP(), p.packet.TCP.SourcePort(), p.packet.IP.DestIP(), p.packet.TCP.DestPort())
	if p.packet.TCP.IsSyn() {
		msg += " syn"
	}
	if p.packet.TCP.IsAck() {
		msg += " ack"
	}
	if p.direction == localToRemote {
		msg += ">  "
	}
	if p.direction == remoteToLocal {
		msg += " < "
	}

	msg += fmt.Sprintf("%d. seq %d (exp %d) ack %d", p.packet.PayloadSize(), p.relativeSeqNum, p.expectedAckNum, p.relativeAckNum)
	return msg
}
