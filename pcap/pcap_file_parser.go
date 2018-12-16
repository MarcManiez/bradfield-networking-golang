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
	tcpSegments := make([]TCPSegment, 0)
	sequenceNumberSet := make(map[int]bool)
	for _, ethernetFrame := range pcap.EthernetFrames() {
		datagram := ethernetFrame.Datagram()
		tcpSegment := datagram.Payload()
		sequenceNumberAlreadyHandled := sequenceNumberSet[tcpSegment.SequenceNumber()]
		if tcpSegment.SourcePort() == 80 && !sequenceNumberAlreadyHandled {
		tcpSegments = append(tcpSegments, tcpSegment)
			sequenceNumberSet[tcpSegment.SequenceNumber()] = true
	}
	}
	fmt.Printf("Test segment source port: %d\n", tcpSegments[0].SequenceNumber())
	sort.SliceStable(tcpSegments, func(i, j int) bool {
		return tcpSegments[i].SequenceNumber() < tcpSegments[j].SequenceNumber()
	})
}
