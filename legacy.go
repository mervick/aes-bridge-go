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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

const (
	blockSize = 16
	keyLen    = 32
	ivLen     = 16
)

// EncryptLegacy encrypts plaintext using AES-256-CBC with OpenSSL-compatible output
// (Salted__ + salt + ciphertext), then base64-encodes the result.
//
// @param data: Plaintext data to encrypt
// @param passphrase: Passphrase for key derivation
// @return: Encrypted data, base64-encoded
func EncryptLegacy(data, passphrase any) (string, error) {
	p, err := toBytes(passphrase)
	if err != nil {
		return "", err
	}
	raw, err := toBytes(data)
	if err != nil {
		return "", err
	}

	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key, iv := deriveKeyAndIV(p, salt)
	padded := pkcs7Pad(raw)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(padded))
	mode.CryptBlocks(encrypted, padded)

	result := append([]byte("Salted__"), salt...)
	result = append(result, encrypted...)

	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(result)))
	base64.StdEncoding.Encode(encoded, result)

	return string(encoded), nil
}

// DecryptLegacy decrypts base64-encoded AES-CBC data with OpenSSL-compatible format
// (Salted__ + salt + ciphertext).
//
// @param data: Encrypted data, base64-encoded
// @param passphrase: Passphrase for key derivation
// @return: Decrypted plaintext as raw bytes
func DecryptLegacy(data, passphrase any) (string, error) {
	enc, err := toBytes(data)
	if err != nil {
		return "", err
	}
	p, err := toBytes(passphrase)
	if err != nil {
		return "", err
	}

	raw := make([]byte, base64.StdEncoding.DecodedLen(len(enc)))
	n, err := base64.StdEncoding.Decode(raw, enc)
	if err != nil {
		return "", err
	}
	raw = raw[:n]

	if len(raw) < 16 || !bytes.Equal(raw[:8], []byte("Salted__")) {
		return "", errors.New("invalid OpenSSL format")
	}

	salt := raw[8:16]
	key, iv := deriveKeyAndIV(p, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCDecrypter(block, iv)

	encrypted := raw[16:]
	if len(encrypted)%aes.BlockSize != 0 {
		return "", errors.New("invalid ciphertext length")
	}

	decrypted := make([]byte, len(encrypted))
	mode.CryptBlocks(decrypted, encrypted)

	unpadded, err := pkcs7Unpad(decrypted)
	if err != nil {
		return "", err
	}

	return string(unpadded), nil
}

// deriveKeyAndIV derives key and IV using OpenSSL-compatible method (EVP_BytesToKey with MD5).
//
// @param password: User passphrase
// @param salt: 8-byte salt
// @return: AES key and IV
func deriveKeyAndIV(password, salt []byte) ([]byte, []byte) {
	var d, d_i []byte
	for len(d) < keyLen+ivLen {
		h := md5.New()
		h.Write(d_i)
		h.Write(password)
		h.Write(salt)
		d_i = h.Sum(nil)
		d = append(d, d_i...)
	}
	return d[:keyLen], d[keyLen : keyLen+ivLen]
}

// pkcs7Pad applies PKCS#7 padding to data.
func pkcs7Pad(data []byte) []byte {
	padLen := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

// pkcs7Unpad removes PKCS#7 padding from data.
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}
	padLen := int(data[len(data)-1])
	if padLen > blockSize || padLen == 0 || len(data) < padLen {
		return nil, errors.New("invalid padding")
	}
	for _, b := range data[len(data)-padLen:] {
		if int(b) != padLen {
			return nil, errors.New("invalid padding content")
		}
	}
	return data[:len(data)-padLen], nil
}
