// This file is part of AesBridge - modern cross-language AES encryption library
// Repository: https://github.com/mervick/aes-bridge
//
// Copyright Andrey Izman (c) 2018-2025 <izmanw@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package aesbridge

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync/atomic"
)

var nonceCounter uint64

func generateRandom(size int) []byte {
	nonce := atomic.AddUint64(&nonceCounter, 1)
	b := make([]byte, 13+8+13)
	rand.Read(b[:13])
	copy(b[13:21], u64ToBytes(nonce))
	rand.Read(b[21:])
	hash := sha256.Sum256(b)
	return hash[:size]
}

func u64ToBytes(n uint64) []byte {
	out := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		out[i] = byte(n)
		n >>= 8
	}
	return out
}

func toBytes(data any) ([]byte, error) {
	switch v := data.(type) {
	case string:
		return []byte(v), nil
	case []byte:
		return v, nil
	default:
		return nil, errors.New("unsupported type")
	}
}

func toString(data any) (string, error) {
	switch v := data.(type) {
	case string:
		return v, nil
	case []byte:
		return string(v), nil
	default:
		return "", errors.New("unsupported type")
	}
}
