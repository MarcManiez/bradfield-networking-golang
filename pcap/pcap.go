package main

import (
	"bytes"
	"encoding/binary"
	"os"
)

// A Pcap is a wrapper around pcap file
type Pcap struct {
	File       []byte
	Endianness binary.ByteOrder
}

// DataLinkTypeMapping maps network header field to a link type
var DataLinkTypeMapping = map[uint32]string{
	0: "null",
	1: "ethernet",
}

// HeaderSize describes the size of the Pcap file header
const HeaderSize = 24

// NewPcap constructs a pcap file
func NewPcap(file *os.File) Pcap {
	stat, err := file.Stat()
	check(err)
	fileBytes := make([]byte, stat.Size())
	_, err = file.ReadAt(fileBytes, 0)
	check(err)
	pcap := Pcap{File: fileBytes}
	defaultEndianness := binary.BigEndian
	expectedMagicBytes := []byte{0xa1, 0xb2, 0xc3, 0xd4}
	actualMagicBytes := pcap.MagicNumberBytes()
	expectedMagicNumber := BytesToIntForEndianness(expectedMagicBytes, defaultEndianness)
	actualMagicNumber := BytesToIntForEndianness(actualMagicBytes, defaultEndianness)

	if expectedMagicNumber == actualMagicNumber {
		pcap.Endianness = defaultEndianness
	} else {
		pcap.Endianness = binary.LittleEndian
	}
	return pcap
}

// Size returns the size of the pcap file
func (p *Pcap) Size() int {
	return len(p.File)
}

// MagicNumberBytes returns the pcap's magic number
func (p *Pcap) MagicNumberBytes() []byte {
	return p.File[0:4]
}

// LinkType returns link type for pcap file
func (p *Pcap) LinkType() string {
	var linkTypeInt uint32
	buffer := bytes.NewReader(p.File[20:24])
	err := binary.Read(buffer, p.Endianness, &linkTypeInt)
	check(err)
	return DataLinkTypeMapping[linkTypeInt]
}

// Payload returns the payload of the pcap file
func (p *Pcap) Payload() []byte {
	return p.File[HeaderSize:p.Size()]
}

// EthernetFrames returns the ethernet frames of the Pcap file
func (p *Pcap) EthernetFrames() []EthernetFrame {
	var frames = make([]EthernetFrame, 0)
	var offset int
	for offset < p.Size() {
		payloadLengthBytes := p.File[offset+8 : offset+12]
		payloadLength := BytesToIntForEndianness(payloadLengthBytes, p.Endianness)
		endOfPacket := offset + 16 + payloadLength
		ethernetFrame := EthernetFrame{Data: p.File[offset+16 : endOfPacket]}
		frames = append(frames, ethernetFrame)
		offset = endOfPacket
	}
	return frames
}
