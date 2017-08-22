package packet

import (
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
func (f *Packet) PayloadSize() uint16 {
	return f.IP.TotalLength() - f.IP.HeaderLength() - f.TCP.HeaderSize()
}

type processPacketFunc func(f *Packet) error

func LoadFromFile(r io.Reader) ([]*Packet, error) {
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
