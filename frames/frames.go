package frames

import (
	"io"
	"jakub-m/bdp/pcap"
)

type Frame struct {
	Record *pcap.PcapRecord
	Ether  *pcap.Ether
	IP     *pcap.IpFrame
	TCP    *pcap.TcpFrame
}

// PayloadSize returns size of TCP payload.
func (f *Frame) PayloadSize() uint16 {
	return f.IP.TotalLength() - f.IP.HeaderLength() - f.TCP.HeaderSize()
}

type processFrameFunc func(f *Frame) error

func LoadFromFile(r io.Reader) ([]*Frame, error) {
	frames := []*Frame{}

	p, err := pcap.NewPcap(r)
	if err != nil {
		return nil, err
	}

	for {
		record, err := p.NextRecord()
		if err == io.EOF {
			return frames, nil
		}
		if err != nil {
			return nil, err
		}

		frame, err := createFrameFromRecord(record)
		if err != nil {
			return nil, err
		}
		frames = append(frames, frame)
	}
}

func createFrameFromRecord(record *pcap.PcapRecord) (*Frame, error) {
	eth, err := pcap.ParseEtherFrame(record.Data)
	if err != nil {
		return nil, err
	}

	ip, err := pcap.ParseIPV4Frame(eth.Data)
	if err != nil {
		return nil, err
	}

	tcp, err := pcap.ParseTCPFrame(ip.Data)
	if err != nil {
		return nil, err
	}

	return &Frame{
		Record: record,
		Ether:  eth,
		IP:     ip,
		TCP:    tcp,
	}, nil
}
