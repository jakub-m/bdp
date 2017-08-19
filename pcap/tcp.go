package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// https://en.wikipedia.org/wiki/Transmission_Control_Protocol
type tcpHdr struct {
	SourcePort    uint16
	DestPort      uint16
	SeqNum        uint32
	AckNum        uint32
	Offset_Flags  uint16
	WindowSize    uint16
	Checksum      uint16
	UrgentPointer uint16
}

type tcpFrame struct {
	hdr *tcpHdr
}

func (f *tcpFrame) String() string {
	return fmt.Sprintf("TCP %+v", f.hdr)
}

func ParseTCPFrame(raw []byte) (*tcpFrame, error) {
	reader := bytes.NewReader(raw)
	header := &tcpHdr{}
	err := binary.Read(reader, binary.BigEndian, header)
	if err != nil {
		return nil, err
	}

	return &tcpFrame{
		hdr: header,
	}, nil
}
