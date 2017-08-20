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
	fn := func(f *Frame) error {
		frames = append(frames, f)
		return nil
	}
	err := processFrames(r, fn)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return frames, nil
}

func processFrames(r io.Reader, fn processFrameFunc) error {
	p, err := pcap.NewPcap(r)
	if err != nil {
		return err
	}

	for {
		record, err := p.NextRecord()
		if err != nil {
			return err
		}

		eth, err := pcap.ParseEtherFrame(record.Data)
		if err != nil {
			return err
		}

		ip, err := pcap.ParseIPV4Frame(eth.Data)
		if err != nil {
			return err
		}

		tcp, err := pcap.ParseTCPFrame(ip.Data)
		if err != nil {
			return err
		}

		err = fn(&Frame{
			Record: record,
			Ether:  eth,
			IP:     ip,
			TCP:    tcp,
		})
		if err != nil {
			return err
		}
	}
}
