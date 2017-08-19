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
	SeqNum        SeqNum
	AckNum        SeqNum
	Offset_Flags  uint16
	WindowSize    uint16
	Checksum      uint16
	UrgentPointer uint16
}

type SeqNum uint32

func (s SeqNum) RelativeTo(r SeqNum) uint32 {
	return uint32(s) - uint32(r)
}

type TcpFrame struct {
	hdr *tcpHdr
}

func (f *TcpFrame) String() string {
	syn := ""
	ack := ""
	if f.IsSyn() {
		syn = "syn "
	}
	if f.IsAck() {
		ack = "ack "
	}
	return fmt.Sprintf("TCP %s%s%+v", syn, ack, f.hdr)
}

func (f *TcpFrame) IsSyn() bool {
	return f.hdr.Offset_Flags&0x0002 != 0
}

func (f *TcpFrame) IsAck() bool {
	return f.hdr.Offset_Flags&0x0010 != 0
}

func (f *TcpFrame) SeqNum() SeqNum {
	return f.hdr.SeqNum
}

func (f *TcpFrame) AckNum() SeqNum {
	return f.hdr.AckNum
}

func (f *TcpFrame) SourcePort() uint16 {
	return f.hdr.SourcePort
}

func (f *TcpFrame) DestPort() uint16 {
	return f.hdr.DestPort
}

// HeaderSize gives size of the TCP header in bytes.
func (f *TcpFrame) HeaderSize() uint16 {
	return (f.hdr.Offset_Flags & 0xF000 >> 12) * 4
}

func ParseTCPFrame(raw []byte) (*TcpFrame, error) {
	reader := bytes.NewReader(raw)
	header := &tcpHdr{}
	err := binary.Read(reader, binary.BigEndian, header)
	if err != nil {
		return nil, err
	}

	return &TcpFrame{
		hdr: header,
	}, nil
}
