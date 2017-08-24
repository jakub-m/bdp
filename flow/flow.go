package flow

import (
	"fmt"
	"jakub-m/bdp/packet"
	"jakub-m/bdp/pcap"
	"log"
)

const (
	usecInSec = 1000 * 1000
)

func ProcessPackets(packets []*packet.Packet) error {
	flow := &flow{
		gotSyn:    false,
		gotSynAck: false,
	}

	for _, f := range packets {
		if fp, err := flow.consumePacket(f); err == nil {
			fmt.Println(fp.String())
		} else {
			log.Println(err)
		}
	}
	return nil
}

// initTimestamp initial timestamp in microseconds
// local is the side that initiates connection (syn).
// remote is the other side of the connection (syn ack).
// inflight are the files that are sent from local to remote and are not yet acknowledged.
// deliveredTime is time of the most recent ACK, as in BBR paper.
// delivered is sum of bytes delivered, as in BBR paper.
type flow struct {
	initTimestamp uint64
	gotSyn        bool
	gotSynAck     bool
	local         flowDetails
	remote        flowDetails
	inflight      []*flowPacket
	stats         []*flowStat
	deliveredTime uint64
	delivered     uint32
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
	deliveredTime     uint64
	delivered         uint32
}

type flowPacketDirection int

const (
	localToRemote flowPacketDirection = iota
	remoteToLocal
)

func (f *flow) consumePacket(packet *packet.Packet) (*flowPacket, error) {
	// TODO: Handle flows without syn and syn+ack, and out-of-order.
	if packet.TCP.IsSyn() && !packet.TCP.IsAck() {
		flowPacket := f.createSynFlowPacket(packet)
		f.onSyn(flowPacket)
		return flowPacket, nil
	} else if packet.TCP.IsSyn() && packet.TCP.IsAck() {
		flowPacket := f.createSynAckFlowPacket(packet)
		f.onSynAck(flowPacket)
		return flowPacket, nil
	} else {
		flowPacket := f.createFlowPacket(packet)
		if flowPacket.direction == localToRemote {
			err := f.onSend(flowPacket)
			if err != nil {
				return nil, err
			}
		} else if flowPacket.direction == remoteToLocal && flowPacket.packet.TCP.IsAck() {
			f.onAck(flowPacket)
		} else {
			panic("direction not set!")
		}
		return flowPacket, nil
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
func (f *flow) onSend(p *flowPacket) error {
	if p.packet.PayloadSize() == 0 {
		return nil
	}
	// Assert that packets are sorted by expectedAckNum.
	if len(f.inflight) > 0 {
		lastInflight := f.inflight[len(f.inflight)-1]
		if lastInflight.expectedAckNum >= p.expectedAckNum {
			return fmt.Errorf("Wrong order of expectedAckNum. last inflight %s, current %s", lastInflight, p)
		}
	}
	p.delivered = f.delivered
	p.deliveredTime = f.deliveredTime
	f.inflight = append(f.inflight, p)
	return nil
}

func (f *flow) onAck(ack *flowPacket) {
	sent, i, ok := f.findPacketSent(ack)
	if !ok {
		return
	}

	rtt := ack.packet.Record.Timestamp() - sent.packet.Record.Timestamp()
	f.delivered += uint32(sent.packet.PayloadSize())
	f.deliveredTime = ack.packet.Record.Timestamp()
	deliveryRate := usecInSec * float32(f.delivered-sent.delivered) / float32(f.deliveredTime-sent.deliveredTime)

	stat := &flowStat{
		// Note that relativeTimestampUSec is the timestmap of the ACK-ing packet, not the original packet.
		relativeTimestampUSec: ack.relativeTimestamp,
		rttUSec:               rtt,
	}
	log.Printf("Got ack for inflight packet: ackNum=%d, rate=%.1fkb/s, %s", ack.relativeAckNum, deliveryRate/1000*8, stat)
	f.stats = append(f.stats, stat)
	f.inflight = f.inflight[i+1:]
}

func (f *flow) findPacketSent(ack *flowPacket) (sent *flowPacket, inflightIndex int, ok bool) {
	for i, g := range f.inflight {
		if ack.relativeAckNum == g.expectedAckNum {
			return g, i, true
		}
	}
	return nil, -1, false
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

// Single data point for flow statistics.
type flowStat struct {
	relativeTimestampUSec uint64
	rttUSec               uint64
}

func (s *flowStat) String() string {
	return fmt.Sprintf("ts: %d msec, rtt: %d msec", s.relativeTimestampUSec/1000, s.rttUSec/1000)
}
