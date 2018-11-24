package main

import (
	"fmt"
	"os"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	file, err := os.Open("net.cap")
	check(err)

	pcap := NewPcap(file)
	fmt.Printf("magic number: %s\n", pcap.MagicNumber())
	fmt.Printf("reverse endianness: %t\n", pcap.ReverseEndianness)
}
