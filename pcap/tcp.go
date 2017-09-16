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

func (s SeqNum) RelativeTo(r SeqNum) SeqNum {
	return SeqNum(uint32(s) - uint32(r))
}

func (s SeqNum) ExpectedForPayload(size uint16) SeqNum {
	return SeqNum(uint32(s) + uint32(size))
}

type TcpPacket struct {
	hdr *tcpHdr
}

func (f *TcpPacket) String() string {
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

func (f *TcpPacket) IsSyn() bool {
	return f.hdr.Offset_Flags&0x0002 != 0
}

func (f *TcpPacket) IsAck() bool {
	return f.hdr.Offset_Flags&0x0010 != 0
}

func (f *TcpPacket) SeqNum() SeqNum {
	return f.hdr.SeqNum
}

func (f *TcpPacket) AckNum() SeqNum {
	return f.hdr.AckNum
}

func (f *TcpPacket) SourcePort() uint16 {
	return f.hdr.SourcePort
}

func (f *TcpPacket) DestPort() uint16 {
	return f.hdr.DestPort
}

// HeaderSize gives size of the TCP header in bytes.
func (f *TcpPacket) HeaderSize() uint16 {
	return (f.hdr.Offset_Flags & 0xF000 >> 12) * 4
}

func (f *TcpPacket) WindowSize() uint16 {
	return f.hdr.WindowSize
}

func ParseTCPPacket(raw []byte) (*TcpPacket, error) {
	reader := bytes.NewReader(raw)
	header := &tcpHdr{}
	err := binary.Read(reader, binary.BigEndian, header)
	if err != nil {
		return nil, err
	}

	return &TcpPacket{
		hdr: header,
	}, nil
}
