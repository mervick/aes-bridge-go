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

// EncryptGCM encrypts data using AES-GCM.
//
// The function returns encrypted ciphertext as a base64-encoded string,
// or an error if the encryption fails.
//
// The ciphertext is the concatenation of the salt, nonce, ciphertext and
// authentication tag produced by EncryptGCMBin.
func Encrypt(data, passphrase any) (string, error) {
	return EncryptGCM(data, passphrase)
}

// DecryptGCM decrypts a base64-encoded string using AES-GCM.
//
// It first decodes the base64-encoded input, and then uses DecryptGCMBin
// to perform the actual decryption.
//
// Returns the decrypted plaintext as a string, or an error if the decryption fails.
func Decrypt(data, passphrase any) (string, error) {
	return DecryptGCM(data, passphrase)
}
