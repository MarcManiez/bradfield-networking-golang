package main

import "encoding/binary"

// TCPSegment adds convenience methods over a slice of bytes
type TCPSegment struct {
	Data               []byte
	ContainingDatagram *Datagram
}

// HeaderLength returns the TCP segment's header length in bytes
func (s *TCPSegment) HeaderLength() int {
	dataOffset := s.Data[12] >> 4
	return int(dataOffset * 4)
}

// Flags returns the TCP segment's flags
func (s *TCPSegment) Flags() byte {
	return s.Data[13]
}

// PayloadLength returns the TCP segment's payload length
func (s *TCPSegment) PayloadLength() int {
	return s.ContainingDatagram.TotalLength() - s.ContainingDatagram.HeaderLength() - s.HeaderLength()
}

// SourcePort returns the TCP segment's source port
func (s *TCPSegment) SourcePort() int {
	return BytesToIntForEndianness16(s.Data[0:2], binary.BigEndian)
}

// DestinationPort returns the TCP segment's destination port
func (s *TCPSegment) DestinationPort() int {
	return BytesToIntForEndianness16(s.Data[2:4], binary.BigEndian)
}

// SequenceNumber returns the TCP segment's sequence number
func (s *TCPSegment) SequenceNumber() int {
	return BytesToIntForEndianness(s.Data[4:8], binary.BigEndian)
}

// ACKNumber returns the TCP segment's ACK number
func (s *TCPSegment) ACKNumber() int {
	return BytesToIntForEndianness(s.Data[8:12], binary.BigEndian)
}

// Payload returns the TCP segment's payload
func (s *TCPSegment) Payload() []byte {
	return s.Data[s.HeaderLength() : s.HeaderLength()+s.PayloadLength()]
}

// SYN tells us if the segment is of type SYN
func (s *TCPSegment) SYN() bool {
	return int(s.Flags()&0x04) > 0
}

// ACK tells us if the segment is of type ACK
func (s *TCPSegment) ACK() bool {
	return int(s.Flags()&0x20) > 0
}

// FIN tells us if the segment is of type FIN
func (s *TCPSegment) FIN() bool {
	return int(s.Flags()&0x02) > 0
}
