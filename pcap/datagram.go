package main

import (
	"encoding/binary"
	"strconv"
)

// ProtocolMap maps header numbers to protocols
var ProtocolMap = map[int]string{
	4:  "IP",
	6:  "TCP",
	17: "UDP",
}

// Datagram adds convenience methods over an array of bytes
type Datagram struct {
	Data []byte
}

// Version returns the IP version of the datagram
func (d *Datagram) Version() int {
	return int(d.Data[0] >> 4)
}

// HeaderLength returns the datagram's header length in bytes
func (d *Datagram) HeaderLength() int {
	// Multiplied by 4 because field unit is words
	return int(d.Data[0]&0x0f) * 4
}

// TotalLength returns the total length of the datagram in bytes
func (d *Datagram) TotalLength() int {
	return BytesToIntForEndianness(d.Data[2:4], binary.BigEndian)
}

// PayloadLength returns datagram's payload lenght in bytes
func (d *Datagram) PayloadLength() int {
	return d.TotalLength() - d.HeaderLength()
}

// Protocol returns the datagram payload's protocol
func (d *Datagram) Protocol() string {
	protocolHeaderNumber := BytesToIntForEndianness(d.Data[9:10], binary.BigEndian)
	return ProtocolMap[protocolHeaderNumber]
}

// SourceIP returns datagram's source IP address
func (d *Datagram) SourceIP() string {
	return BytesToIPAddress(d.Data[12:16])
}

// DestinationIP returns datagram's destination IP address
func (d *Datagram) DestinationIP() string {
	return BytesToIPAddress(d.Data[16:20])
}

// Payload returns the datagram's payload
func (d *Datagram) Payload() TCPSegment {
	data := d.Data[d.HeaderLength():d.TotalLength()]
	// TODO: use Protocol() to return different structs based on Protocol
	// this will require us to modify the return type as well
	return TCPSegment{Data: data, ContainingDatagram: d}
}

// BytesToIPAddress takes a byte slice and returns a string with ":" interpolated
func BytesToIPAddress(bytes []byte) string {
	address := ""
	for _, b := range bytes {
		if len(address) > 0 {
			address += ":"
		}
		address += strconv.Itoa(int(b))
	}
	return address
}
