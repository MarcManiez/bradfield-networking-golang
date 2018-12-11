package main

import (
	"fmt"
	"os"
	"sort"
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
	fmt.Printf("magic number: %s\n", pcap.LinkType())
	tcpSegments := make([]TCPSegment, 0)
	for _, ethernetFrame := range pcap.EthernetFrames() {
		datagram := ethernetFrame.Datagram()
		tcpSegment := datagram.Payload()
		tcpSegments = append(tcpSegments, tcpSegment)
	}
	sort.SliceStable(tcpSegments, func(i, j int) bool {
		return tcpSegments[i].SequenceNumber() < tcpSegments[j].SequenceNumber()
	})
}
