package packet

import (
	"fmt"
	"io"
	"jakub-m/bdp/pcap"
)

type Packet struct {
	Record *pcap.PcapRecord
	Ether  *pcap.Ether
	IP     *pcap.IpPacket
	TCP    *pcap.TcpPacket
}

// PayloadSize returns size of TCP payload.
func (p *Packet) PayloadSize() uint16 {
	return p.IP.TotalLength() - p.IP.HeaderLength() - p.TCP.HeaderSize()
}

func (p *Packet) String() string {
	return fmt.Sprintf("%dB %s %s", p.Record.OrigLen(), p.IP, p.TCP)
}

type processPacketFunc func(f *Packet) error

// onError is called on packet read errors, return value is "should continue" - will break on false.
func LoadFromFile(r io.Reader, onError func(error) bool) ([]*Packet, error) {
	packets := []*Packet{}

	p, err := pcap.NewPcap(r)
	if err != nil {
		return nil, err
	}

	for {
		record, err := p.NextRecord()
		if err == io.EOF {
			return packets, nil
		}
		if err != nil {
			return nil, err
		}

		packet, err := createPacketFromRecord(record)
		if err != nil {
			if shouldContinue := onError(err); shouldContinue {
				continue
			}
			return nil, err
		}
		packets = append(packets, packet)
	}
}

func createPacketFromRecord(record *pcap.PcapRecord) (*Packet, error) {
	eth, err := pcap.ParseEtherPacket(record.Data)
	if err != nil {
		return nil, err
	}

	ip, err := pcap.ParseIPV4Packet(eth.Data)
	if err != nil {
		return nil, err
	}

	tcp, err := pcap.ParseTCPPacket(ip.Data)
	if err != nil {
		return nil, err
	}

	return &Packet{
		Record: record,
		Ether:  eth,
		IP:     ip,
		TCP:    tcp,
	}, nil
}
