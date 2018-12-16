package main

import "bytes"

// HTTPRequest adds convenience methods over a slice of bytes
type HTTPRequest struct {
	Data []byte
}

// Lines returns the different lines of the HTML request
func (r *HTTPRequest) Lines() [][]byte {
	return bytes.Split(r.Data, []byte("\x0d\x0a"))
}

// Body returns the HTTP request's body
func (r *HTTPRequest) Body() []byte {
	return r.Lines()[len(r.Lines())-1]
}
