// Package aesbridge provides AES-CBC encryption with HMAC authentication.
// This file is part of AesBridge - modern cross-language AES encryption library
// Repository: https://github.com/mervick/aes-bridge
//
// Copyright Andrey Izman (c) 2018-2025 <izmanw@gmail.com>
// Licensed under the MIT license.

package aesbridge

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "golang.org/x/crypto/pbkdf2"
    "errors"
)

// deriveKeys derives AES and HMAC keys using PBKDF2 with SHA-256.
func deriveKeys(passphrase, salt []byte) (aesKey, hmacKey []byte) {
    key := pbkdf2.Key(passphrase, salt, 100_000, 64, sha256.New)
    return key[:32], key[32:]
}

// EncryptCBCBin encrypts data using AES-CBC mode with HMAC authentication.
//
// @param data: Data to encrypt
// @param passphrase: Encryption passphrase
//
// @return: Encrypted data in format: salt (16 bytes) + IV (16 bytes) +
//          ciphertext (variable length) + HMAC tag (32 bytes)
//            as a string, or an error if the encryption fails.
func EncryptCBCBin(data, passphrase any) (string, error) {
    p, err := toBytes(passphrase)
    if err != nil {
        return "", err
    }
    plaintext, err := toBytes(data)
    if err != nil {
        return "", err
    }

    salt := make([]byte, 16)
    iv := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return "", err
    }
    if _, err := rand.Read(iv); err != nil {
        return "", err
    }

    aesKey, hmacKey := deriveKeys(p, salt)

    block, err := aes.NewCipher(aesKey)
    if err != nil {
        return "", err
    }

    padLen := aes.BlockSize - len(plaintext)%aes.BlockSize
    padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
    padded := append(plaintext, padding...)

    mode := cipher.NewCBCEncrypter(block, iv)
    ciphertext := make([]byte, len(padded))
    mode.CryptBlocks(ciphertext, padded)

    mac := hmac.New(sha256.New, hmacKey)
    mac.Write(append(iv, ciphertext...))
    tag := mac.Sum(nil)

    encrypted := append(append(append(salt, iv...), ciphertext...), tag...)
    return string(encrypted), nil
}

// DecryptCBCBin decrypts data encrypted with EncryptCBCBin() function.
//
// @param data: Encrypted data in format from EncryptCBCBin():
//              salt (16) + IV (16) + ciphertext (N) + HMAC (32)
// @param passphrase: passphrase used for encryption
// @return: The decrypted plaintext as a string, or an error if the decryption fails.
func DecryptCBCBin(data, passphrase any) (string, error) {
    raw, err := toBytes(data)
    if err != nil {
        return "", err
    }
    if len(raw) < 64 {
        return "", errors.New("Data too short")
    }

    p, err := toBytes(passphrase)
    if err != nil {
        return "", err
    }

    salt := raw[:16]
    iv := raw[16:32]
    tag := raw[len(raw)-32:]
    ciphertext := raw[32 : len(raw)-32]

    aesKey, hmacKey := deriveKeys(p, salt)

    mac := hmac.New(sha256.New, hmacKey)
    mac.Write(append(iv, ciphertext...))
    expected := mac.Sum(nil)
    if !hmac.Equal(tag, expected) {
        return "", errors.New("HMAC verification failed")
    }

    block, err := aes.NewCipher(aesKey)
    if err != nil {
        return "", err
    }

    if len(ciphertext)%aes.BlockSize != 0 {
        return "", errors.New("invalid ciphertext length")
    }

    mode := cipher.NewCBCDecrypter(block, iv)
    padded := make([]byte, len(ciphertext))
    mode.CryptBlocks(padded, ciphertext)

    padLen := int(padded[len(padded)-1])
    if padLen == 0 || padLen > aes.BlockSize {
        return "", errors.New("invalid padding")
    }
    return string(padded[:len(padded)-padLen]), nil
}

// EncryptCBC encrypts data and returns result as base64 encoded bytes.
//
// @param data: Data to encrypt
// @param passphrase: Encryption passphrase
func EncryptCBC(data, passphrase any) (string, error) {
    encrypted, err := EncryptCBCBin(data, passphrase)
    if err != nil {
        return "", err
    }

    encryptedBytes, err := toBytes(encrypted)
    if err != nil {
        return "", err
    }

    dst := make([]byte, base64.StdEncoding.EncodedLen(len(encryptedBytes)))
    base64.StdEncoding.Encode(dst, encryptedBytes)
    return string(dst), nil
}

// DecryptCBC decrypts base64 encoded data encrypted with EncryptCBC().
//
// @param data: Base64 encoded encrypted data
// @param passphrase: Encryption passphrase
func DecryptCBC(data, passphrase any) (string, error) {
    dataStr, err := toString(data)
    if err != nil {
        return "", err
    }
    decoded, err := base64.StdEncoding.DecodeString(dataStr)
    if err != nil {
        return "", err
    }
    return DecryptCBCBin(decoded, passphrase)
}
