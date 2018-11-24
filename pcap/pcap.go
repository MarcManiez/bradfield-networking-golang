package main

import (
	"encoding/hex"
	"os"
)

// A Pcap is a wrapper around pcap file.
type Pcap struct {
	File              *os.File
	ReverseEndianness bool
}

// NewPcap constructs a pcap file
func NewPcap(file *os.File) Pcap {
	pcap := Pcap{File: file}
	pcap.ReverseEndianness = pcap.MagicNumber() != "a1b2c3d4"
	return pcap
}

// Size returns the size of the pcap file.
func (p *Pcap) Size() int64 {
	stat, err := p.File.Stat()
	check(err)
	return stat.Size()
}

// MagicNumber returns the pcap's magic number
func (p *Pcap) MagicNumber() string {
	buffer := make([]byte, 4)
	_, err := p.File.ReadAt(buffer, 0)
	check(err)
	return hex.EncodeToString(buffer)
}

// make a pcap packet struct
// make properties for:
// each one of its header fields
// its size
// its entire contents
// header
// contents
