package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// https://en.wikipedia.org/wiki/IPv4
type ipHdr struct {
	Version_IHL          uint8
	DSCP_ECN             uint8
	TotalLength          uint16
	Identification       uint16
	Flags_FragmentOffset uint16
	TimeToLive           uint8
	Protocol             uint8
	HeaderChecksum       uint16
	SourceIP             [4]uint8
	DestIP               [4]byte
}

func (h *ipHdr) version() uint8 {
	return h.Version_IHL & 0xF0 >> 4
}

func (h *ipHdr) headerLength() uint8 {
	return (h.Version_IHL & 0x0F) * 4
}

type ipFrame struct {
	hdr  *ipHdr
	Data []byte
}

func (f *ipFrame) String() string {
	return fmt.Sprintf("IP {Ver %d, hdr length %d, %+v, data=%d}", f.hdr.version(), f.hdr.headerLength(), f.hdr, len(f.Data))
}

func ParseIPV4Frame(raw []byte) (*ipFrame, error) {
	reader := bytes.NewReader(raw)
	header := &ipHdr{}
	err := binary.Read(reader, binary.BigEndian, header)
	if err != nil {
		return nil, err
	}

	if header.version() != 4 {
		return nil, fmt.Errorf("Expected IP version 4 , got %#x", header.version())
	}

	return &ipFrame{
		hdr:  header,
		Data: raw[header.headerLength():],
	}, nil
}
