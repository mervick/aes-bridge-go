# AesBridge GO

[![CI Status](https://github.com/mervick/aes-bridge-go/actions/workflows/go-tests.yml/badge.svg)](https://github.com/mervick/aes-bridge-go/actions/workflows/go-tests.yml)


**AesBridge** is a modern, secure, and cross-language **AES** encryption library. It offers a unified interface for encrypting and decrypting data across multiple programming languages. Supports **GCM**, **CBC**, and **legacy AES Everywhere** modes.


This is the **GO implementation** of the core project.  
👉 Main repository: https://github.com/mervick/aes-bridge

## Features

- 🔐 AES-256 encryption in GCM (recommended) and CBC modes
- 🌍 Unified cross-language design
- 📦 Compact binary format or base64 output
- ✅ HMAC Integrity: CBC mode includes HMAC verification
- 🔄 Backward Compatible: Supports legacy AES Everywhere format


### Installation

```go
import "github.com/mervick/aes-bridge-go"
```

### Usage

```go
package main

import (
	"fmt"
	"github.com/mervick/aes-bridge-go"
)

func main() {
	ciphertext, err := aesbridge.EncryptGCM("My secret message", "MyStrongPass")
	if err != nil {
		panic(err)
	}

	plaintext, err := aesbridge.DecryptGCM(ciphertext, "MyStrongPass")
	if err != nil {
		panic(err)
	}

	fmt.Println(plaintext)
}
```


## API Reference

### Main Functions (GCM by default)

- `Encrypt(data any, passphrase any) (string, error)`  
  Encrypts a string using AES-GCM (default).  
  **Returns:** base64-encoded string.
  
- `Decrypt(ciphertext any, passphrase any) (string, error)`  
  Decrypts a base64-encoded string encrypted with AES-GCM.

### GCM Mode (recommended)

- `EncryptGCM(data any, passphrase any) (string, error)`  
  Encrypts a string using AES-GCM.
  **Returns:** base64-encoded string.

- `DecryptGCM(ciphertext any, passphrase any) (string, error)`  
  Decrypts a base64-encoded string encrypted with `EncryptGCM`.

- `EncryptGCMBin(data any, passphrase any) (string, error)`  
  Returns encrypted binary data using AES-GCM.

- `DecryptGCMBin(ciphertext any, passphrase any) (string, error)`  
  Decrypts binary data encrypted with `EncryptGCMBin`.

### CBC Mode

- `EncryptCBC(data any, passphrase any) (string, error)`  
  Encrypts a string using AES-CBC. 
  HMAC is used for integrity verification.  
  **Returns:** base64-encoded string.  

- `DecryptCBC(ciphertext any, passphrase any) (string, error)`  
  Decrypts a base64-encoded string encrypted with `EncryptCBC` and verifies HMAC.

- `EncryptCBCBin(data any, passphrase any) (string, error)`  
  Returns encrypted binary data using AES-CBC with HMAC.

- `DecryptCBCBin(ciphertext any, passphrase any) (string, error)`  
  Decrypts binary data encrypted with `EncryptCBCBin` and verifies HMAC.

### Legacy Compatibility

⚠️ These functions are kept for backward compatibility only.
Their usage is strongly discouraged in new applications.

- `EncryptLegacy(data any, passphrase any) (string, error)`  
  Encrypts a string in the legacy AES Everywhere format.  

- `DecryptLegacy(ciphertext any, passphrase any) (string, error)`  
  Decrypts a string encrypted in the legacy AES Everywhere format.
