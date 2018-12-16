package main

// EthernetFrame adds convenience methods over a slice of bytes
type EthernetFrame struct {
	Data []byte
}

// MacDestination returns a hex byte string of the mad destination address
func (e *EthernetFrame) MacDestination() []byte {
	return BytesToHex(e.Data[0:6])
}

// MacSource returns a hex byte string of the mad destination address
func (e *EthernetFrame) MacSource() []byte {
	return BytesToHex(e.Data[6:12])
}

// EtherType returns a hex byte string of the mad destination address - We are assuming no tag for the time being.
func (e *EthernetFrame) EtherType() []byte {
	return BytesToHex(e.Data[12:14])
}

// Payload returns a byte slice of the ethernet frame's payload
func (e *EthernetFrame) Payload() []byte {
	return e.Data[14:len(e.Data)]
}

// Datagram returns the datagram for the ethernet frame
func (e *EthernetFrame) Datagram() Datagram {
	return Datagram{Data: e.Payload()}
}
