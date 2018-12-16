package main

import (
	"fmt"
	"io/ioutil"
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
	httpRequestBytes := make([]byte, 0)
	for _, tcpSegment := range tcpSegments {
		httpRequestBytes = append(httpRequestBytes, tcpSegment.Payload()...)
	}
	httpRequest := HTTPRequest{Data: httpRequestBytes}

	err = ioutil.WriteFile("image.jpg", httpRequest.Body(), 0644)
	check(err)
}
