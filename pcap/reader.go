package pcap

// Rudimentary support of reading basic info from TCP frames.

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	magicNumber = 0xA1B2C3D4
)

type pcap struct {
	hdr    *pcapGlobalHdr
	reader io.Reader
}

func (p *pcap) String() string {
	return fmt.Sprintf("%+v", p.hdr)
}

// Taken from https://wiki.wireshark.org/Development/LibpcapFileFormat
type pcapGlobalHdr struct {
	MagicNumber  uint32 // magic number
	VersionMajor uint16 // major version
	VersionMinor uint16 // minor version
	Thiszone     int32  // GMT to local correction
	Sigfigs      uint32 // accuracy of timestamps
	Snaplen      uint32 // max length of captured packets, in octets
	Network      uint32 // data link type
}

type pcapRecordHdr struct {
	TSSec   uint32 // timestamp seconds
	TSUsec  uint32 // timestamp microseconds
	InclLen uint32 // number of octets of packet saved in file
	OrigLen uint32 // actual length of packet
}

type PcapRecord struct {
	hdr  *pcapRecordHdr
	Data []byte
}

// Timestamp return microseconds.
func (r *PcapRecord) Timestamp() uint64 {
	return uint64(r.hdr.TSSec)*1000000 + uint64(r.hdr.TSUsec)
}

func (r *PcapRecord) OrigLen() uint32 {
	return r.hdr.OrigLen
}

func (r *PcapRecord) String() string {
	return fmt.Sprintf("%+v, data=%d", r.hdr, len(r.Data))
}

func NewPcap(r io.Reader) (*pcap, error) {
	hdr := &pcapGlobalHdr{}
	err := binary.Read(r, binary.LittleEndian, hdr)
	if err != nil {
		return nil, err
	}
	if hdr.MagicNumber != magicNumber {
		return nil, fmt.Errorf("Expected magic number to be %#x and got %#x", magicNumber, hdr.MagicNumber)
	}
	return &pcap{
		hdr:    hdr,
		reader: r,
	}, nil
}

func (p *pcap) NextRecord() (*PcapRecord, error) {
	hdr := &pcapRecordHdr{}
	err := binary.Read(p.reader, binary.LittleEndian, hdr)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, hdr.InclLen)
	_, err = io.ReadFull(p.reader, buf)
	if err != nil {
		return nil, err
	}
	return &PcapRecord{
		hdr:  hdr,
		Data: buf,
	}, nil
}
