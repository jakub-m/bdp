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
	SourceIP             IPv4
	DestIP               IPv4
}

func (h *ipHdr) version() uint8 {
	return h.Version_IHL & 0xF0 >> 4
}

func (h *ipHdr) headerLength() uint8 {
	return (h.Version_IHL & 0x0F) * 4
}

type IPv4 [4]uint8

func (p IPv4) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", p[0], p[1], p[2], p[3])
}

type IpFrame struct {
	hdr  *ipHdr
	Data []byte
}

func (f *IpFrame) SourceIP() IPv4 {
	return f.hdr.SourceIP
}

func (f *IpFrame) DestIP() IPv4 {
	return f.hdr.DestIP
}

func (f *IpFrame) String() string {
	return fmt.Sprintf("IP {Ver %d, hdr len %d, %s -> %s, data=%d}", f.hdr.version(), f.hdr.headerLength(), f.hdr.SourceIP.String(), f.hdr.DestIP.String(), len(f.Data))
}

func ParseIPV4Frame(raw []byte) (*IpFrame, error) {
	reader := bytes.NewReader(raw)
	header := &ipHdr{}
	err := binary.Read(reader, binary.BigEndian, header)
	if err != nil {
		return nil, err
	}

	if header.version() != 4 {
		return nil, fmt.Errorf("Expected IP version 4 , got %#x", header.version())
	}

	return &IpFrame{
		hdr:  header,
		Data: raw[header.headerLength():],
	}, nil
}
