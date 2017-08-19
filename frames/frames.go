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

type ProcessFrameFunc func(f *Frame) error

func ProcessFrames(r io.Reader, fn ProcessFrameFunc) error {
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
