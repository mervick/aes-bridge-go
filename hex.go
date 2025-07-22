//go:build go1.21
// +build go1.21

package aesbridge

import "encoding/hex"

// FromHex is a wrapper around hex.Decode to support go1.20
func fromHex(dst []byte, src string) (int, error) {
	return hex.Decode(dst, []byte(src))
}

// AppendEncode appends the hex-encoded src to dst and returns the extended
// buffer.
func AppendEncode(dst, src []byte) []byte {
	d := make([]byte, len(src)*2)
	hex.Encode(d, src)
	dst = append(dst, d...)
	return dst
}
