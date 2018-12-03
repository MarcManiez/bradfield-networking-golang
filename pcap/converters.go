package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
)

// BytesToIntForEndianness determines the int for four bytes given an endianness
func BytesToIntForEndianness(byteArray []byte, endianness binary.ByteOrder) int {
	var expectedMagicNumber uint32
	buffer := bytes.NewReader(byteArray)
	err := binary.Read(buffer, endianness, &expectedMagicNumber)
	check(err)
	return int(expectedMagicNumber)
}

// BytesToHex takes a byte array and returns a copy it in hex format
func BytesToHex(byteArray []byte) []byte {
	dst := make([]byte, hex.EncodedLen(len(byteArray)))
	hex.Encode(dst, byteArray)
	return dst
}
