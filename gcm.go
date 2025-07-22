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
    "crypto/aes"
    "crypto/cipher"
    "crypto/sha256"
    "encoding/base64"
    "errors"

    "golang.org/x/crypto/pbkdf2"
)

func deriveKey(passphrase []byte, salt []byte) []byte {
    return pbkdf2.Key(passphrase, salt, 100000, 32, sha256.New)
}

// Encrypts data using AES-GCM.
//
// @param data: Data to encrypt
// @param passphrase: Encryption passphrase
//
// @return: Encrypted data in format: salt(16) + nonce(12) + ciphertext + tag(16)
//
//    as a string, or an error if the decryption fails.
func EncryptGCMBin(data, passphrase any) (string, error) {
    p, err := toBytes(passphrase)
    if err != nil {
        return "", err
    }
    pt, err := toBytes(data)
    if err != nil {
        return "", err
    }

    salt := generateRandom(16)
    nonce := generateRandom(12)
    key := deriveKey(p, salt)

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    ciphertext := aesgcm.Seal(nil, nonce, pt, nil)
    ciphertext = append(append(salt, nonce...), ciphertext...)
    return string(ciphertext), nil
}

// Decrypts data encrypted with EncryptGCMBin.
//
// @param data: Encrypted data in format from EncryptGCMBin():
//
//    salt(16) + nonce(12) + ciphertext + tag(16)
//
// @param passphrase: passphrase used for encryption
// @return: The decrypted plaintext as a string, or an error if the decryption fails.
func DecryptGCMBin(data, passphrase any) (string, error) {
    raw, err := toBytes(data)
    if err != nil {
        return "", err
    }
    if len(raw) < 44 {
        return "", errors.New("data too short")
    }

    p, err := toBytes(passphrase)
    if err != nil {
        return "", err
    }

    salt := raw[:16]
    nonce := raw[16:28]
    tag := raw[len(raw)-16:]
    ciphertext := raw[28 : len(raw)-16]
    key := deriveKey(p, salt)

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    result, err := aesgcm.Open(nil, nonce, append(ciphertext, tag...), nil)
    if err != nil {
        return "", err
    }

    return string(result), nil
}

// EncryptGCM encrypts data using AES-GCM.
//
// The function returns encrypted ciphertext as a base64-encoded string,
// or an error if the encryption fails.
//
// The ciphertext is the concatenation of the salt, nonce, ciphertext and
// authentication tag produced by EncryptGCMBin.
func EncryptGCM(data, passphrase any) (string, error) {
    encrypted, err := EncryptGCMBin(data, passphrase)
    if err != nil {
        return "", err
    }
    enc, err := toBytes(encrypted)
    if err != nil {
        return "", err
    }
    return base64.StdEncoding.EncodeToString(enc), nil
}

// DecryptGCM decrypts a base64-encoded string using AES-GCM.
//
// It first decodes the base64-encoded input, and then uses DecryptGCMBin
// to perform the actual decryption.
//
// Returns the decrypted plaintext as a string, or an error if the decryption fails.
func DecryptGCM(data, passphrase any) (string, error) {
    dataStr, err := toString(data)
    if err != nil {
        return "", err
    }
    decoded, err := base64.StdEncoding.DecodeString(dataStr)
    if err != nil {
        return "", err
    }
    return DecryptGCMBin(decoded, passphrase)
}
