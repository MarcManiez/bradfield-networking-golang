package main

import (
	"bytes"
	"encoding/binary"
	"os"
)

// A Pcap is a wrapper around pcap file
type Pcap struct {
	File       *os.File
	Endianness binary.ByteOrder
}

// DataLinkTypeMapping maps network header field to a link type
var DataLinkTypeMapping = map[uint32]string{
	0: "null",
	1: "ethernet",
}

// NewPcap constructs a pcap file
func NewPcap(file *os.File) Pcap {
	pcap := Pcap{File: file}
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
func (p *Pcap) Size() int64 {
	stat, err := p.File.Stat()
	check(err)
	return stat.Size()
}

// MagicNumberBytes returns the pcap's magic number
func (p *Pcap) MagicNumberBytes() []byte {
	buffer := make([]byte, 4)
	_, err := p.File.ReadAt(buffer, 0)
	check(err)
	return buffer
}

// LinkType returns link type for pcap file
func (p *Pcap) LinkType() string {
	linkTypeBytes := make([]byte, 4)
	_, err := p.File.ReadAt(linkTypeBytes, 20)
	check(err)
	var linkTypeInt uint32
	buffer := bytes.NewReader(linkTypeBytes)
	err = binary.Read(buffer, p.Endianness, &linkTypeInt)
	check(err)
	return DataLinkTypeMapping[linkTypeInt]
}

// make a pcap packet struct
// make properties for:
// each one of its header fields
// its size
// its entire contents
// header
// contents
// packets

// BytesToIntForEndianness determines the int for four bytes given an endianness
func BytesToIntForEndianness(byteArray []byte, endianness binary.ByteOrder) uint32 {
	var expectedMagicNumber uint32
	buffer := bytes.NewReader(byteArray)
	err := binary.Read(buffer, endianness, &expectedMagicNumber)
	check(err)
	return expectedMagicNumber
}
