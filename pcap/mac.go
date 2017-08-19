package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"
)

const (
	etherTypeIPv4 = 0x0800
)

var etherHdrSize int

// https://en.wikipedia.org/wiki/Ethernet_frame
type etherHdr struct {
	MacDest   [6]byte
	MacSrc    [6]byte
	EtherType uint16
}

type Ether struct {
	hdr  *etherHdr
	Data []byte
}

func (e *Ether) String() string {
	return fmt.Sprintf("Ether {dst: %#x, src: %#x, etherType: %#x}", e.hdr.MacDest, e.hdr.MacSrc, e.hdr.EtherType)
}

func init() {
	var etherHdr *etherHdr
	// Any better way to get size of the struct?
	etherHdrSize = int(unsafe.Sizeof(*etherHdr))
}

func ParseEtherFrame(raw []byte) (*Ether, error) {
	reader := bytes.NewReader(raw)
	header := &etherHdr{}
	nRead := 0
	err := binary.Read(reader, binary.BigEndian, header)
	if err != nil {
		return nil, err
	}
	nRead += etherHdrSize

	if header.EtherType != etherTypeIPv4 {
		return nil, fmt.Errorf("Expected IPv4 ethertype, got %#x", header.EtherType)
	}

	return &Ether{
		hdr:  header,
		Data: raw[nRead:],
	}, nil
}
