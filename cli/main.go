package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	aesbridge "github.com/mervick/aes-bridge-go"
)

func main() {

	var (
		mode       string
		action     string
		data       string
		passphrase string
		useB64     bool
	)

	if len(os.Args) < 2 {
		exitErr("Missing action: must be 'encrypt' or 'decrypt'")
	}

	action = os.Args[1]
	if action != "encrypt" && action != "decrypt" {
		exitErr("Invalid action: must be 'encrypt' or 'decrypt'")
	}

	// if len(os.Args) < 3 {
	// 	exitErr("Missing action: must be 'encrypt' or 'decrypt'")
	// }

	fs := flag.NewFlagSet("custom", flag.ExitOnError)

	// flag.StringVar(&action, "action", "", "encrypt or decrypt (required)")
	// flag.StringVar(&mode, "mode", "", "cbc, gcm, or legacy (required)")
	// flag.StringVar(&data, "data", "", "data to encrypt (UTF-8) or decrypt (base64) (required)")
	// flag.StringVar(&passphrase, "passphrase", "", "passphrase for encryption (required)")
	// flag.BoolVar(&useB64, "b64", false, "input/output is base64-encoded")

	modeArg := fs.String("mode", "", "Encryption mode (cbc, gcm, legacy)")
	dataArg := fs.String("data", "", "Encryption mode (cbc, gcm, legacy)")
	passArg := fs.String("passphrase", "", "Passphrase")
	b64Arg := fs.Bool("b64", false, "Base64 encode/decode")

	args := append(os.Args[:1], os.Args[2:]...)
	fs.Parse(args[1:])

	mode = *modeArg
	data = *dataArg
	passphrase = *passArg
	useB64 = *b64Arg

	// fmt.Println("action:", action)
	// fmt.Println("mode:", mode)
	// fmt.Println("passphrase:", passphrase)
	// fmt.Println("b64:", useB64)

	if action != "encrypt" && action != "decrypt" {
		exitErr("Invalid action: must be 'encrypt' or 'decrypt'")
	}
	if mode != "cbc" && mode != "gcm" && mode != "legacy" {
		exitErr("Invalid mode: must be 'cbc', 'gcm' or 'legacy'")
	}
	if data == "" || passphrase == "" {
		exitErr("Missing required arguments: --data and --passphrase are required")
	}

	var (
		result string = ""
		err    error
	)

	if action == "encrypt" && useB64 {
		input, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			exitErr(fmt.Sprintf("Base64 decode error: %v", err))
		}
		data = string(input)
	}

	switch mode {
	case "cbc":
		if action == "encrypt" {
			result, err = aesbridge.EncryptCBC(data, passphrase)
		} else {
			result, err = aesbridge.DecryptCBC(data, passphrase)
			if err == nil && useB64 {
				b := make([]byte, base64.StdEncoding.EncodedLen(len(result)))
				base64.StdEncoding.Encode(b, []byte(result))
				result = string(b)
			}
		}

	case "gcm":
		if action == "encrypt" {
			result, err = aesbridge.EncryptGCM(data, passphrase)
		} else {
			result, err = aesbridge.DecryptGCM(data, passphrase)
			if err == nil && useB64 {
				b := make([]byte, base64.StdEncoding.EncodedLen(len(result)))
				base64.StdEncoding.Encode(b, []byte(result))
				result = string(b)
			}
		}

	case "legacy":
		if action == "encrypt" {
			result, err = aesbridge.EncryptLegacy(data, passphrase)
		} else {
			result, err = aesbridge.DecryptLegacy(data, passphrase)
			if err == nil && useB64 {
				b := make([]byte, base64.StdEncoding.EncodedLen(len(result)))
				base64.StdEncoding.Encode(b, []byte(result))
				result = string(b)
			}
		}
	}

	if err != nil {
		exitErr(fmt.Sprintf("Error: %v", err))
	}
	fmt.Println(result)
}

func exitErr(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
