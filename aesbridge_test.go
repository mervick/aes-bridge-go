package aesbridge

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

type TestData struct {
	Testdata struct {
		Plaintext []string `json:"plaintext"`
		Hex       []string `json:"hex"`
	} `json:"testdata"`
	Decrypt []struct {
		ID              string `json:"id"`
		Plaintext       string `json:"plaintext"`
		Hex             string `json:"hex"`
		Passphrase      string `json:"passphrase"`
		EncryptedCBC    string `json:"encrypted-cbc"`
		EncryptedGCM    string `json:"encrypted-gcm"`
		EncryptedLegacy string `json:"encrypted-legacy"`
	} `json:"decrypt"`
}

func loadTestData(t *testing.T) TestData {
	t.Helper()
	f, err := os.Open("testdata/test_data.json")
	if err != nil {
		t.Fatalf("Failed to open test_data.json: %v", err)
	}
	defer f.Close()

	var data TestData
	if err := json.NewDecoder(f).Decode(&data); err != nil {
		t.Fatalf("Failed to decode test_data.json: %v", err)
	}
	return data
}

func TestAesBridge(t *testing.T) {
	testData := loadTestData(t)

	// Helper function to add tests dynamically
	addTest := func(name string, test func(t *testing.T)) {
		t.Run(name, test)
	}

	// Test functions
	testEncryptCBCNotEmpty := func(value []byte) func(t *testing.T) {
		return func(t *testing.T) {
			encrypted, err := EncryptCBC(value, value)
			if err != nil {
				t.Fatalf("EncryptCBC failed: %v", err)
			}
			if encrypted == "" {
				t.Error("Encryption result should not be empty")
			}
		}
	}

	testEncryptGCMNotEmpty := func(value []byte) func(t *testing.T) {
		return func(t *testing.T) {
			encrypted, err := EncryptGCM(value, value)
			if err != nil {
				t.Fatalf("EncryptGCM failed: %v", err)
			}
			if encrypted == "" {
				t.Error("Encryption result should not be empty")
			}
		}
	}

	testEncryptLegacyNotEmpty := func(value []byte) func(t *testing.T) {
		return func(t *testing.T) {
			encrypted, err := EncryptLegacy(value, value)
			if err != nil {
				t.Fatalf("EncryptLegacy failed: %v", err)
			}
			if encrypted == "" {
				t.Error("Encryption result should not be empty")
			}
		}
	}

	testEncryptDecryptCBC := func(value []byte) func(t *testing.T) {
		return func(t *testing.T) {
			encrypted, err := EncryptCBC(value, value)
			if err != nil {
				t.Fatalf("EncryptCBC failed: %v", err)
			}
			decrypted, err := DecryptCBC(encrypted, value)

			if err != nil {
				t.Fatalf("DecryptCBC failed: %v", err)
			}
			if string(value) != decrypted {
				t.Errorf("CBC encryption/decryption failed: expected %q, got %q", string(value), decrypted)
			}
		}
	}

	testEncryptDecryptGCM := func(value []byte) func(t *testing.T) {
		return func(t *testing.T) {
			encrypted, err := EncryptGCM(value, value)
			if err != nil {
				t.Fatalf("EncryptGCM failed: %v", err)
			}
			decrypted, err := DecryptGCM(encrypted, value)
			if err != nil {
				t.Fatalf("DecryptGCM failed: %v", err)
			}
			if string(value) != decrypted {
				t.Errorf("GCM encryption/decryption failed: expected %q, got %q", string(value), decrypted)
			}
		}
	}

	testEncryptDecryptLegacy := func(value []byte) func(t *testing.T) {
		return func(t *testing.T) {
			encrypted, err := EncryptLegacy(value, value)
			if err != nil {
				t.Fatalf("EncryptLegacy failed: %v", err)
			}
			decrypted, err := DecryptLegacy(encrypted, value)
			if err != nil {
				t.Fatalf("DecryptLegacy failed: %v", err)
			}
			if string(value) != decrypted {
				t.Errorf("Legacy encryption/decryption failed: expected %q, got %q", string(value), decrypted)
			}
		}
	}

	testDecryptCBC := func(encrypted string, passphrase string, result []byte) func(t *testing.T) {
		return func(t *testing.T) {
			decrypted, err := DecryptCBC(encrypted, passphrase)
			if err != nil {
				t.Fatalf("DecryptCBC failed: %v", err)
			}
			if string(result) != decrypted {
				t.Errorf("CBC decryption failed: expected %q, got %q", string(result), decrypted)
			}
		}
	}

	testDecryptGCM := func(encrypted string, passphrase string, result []byte) func(t *testing.T) {
		return func(t *testing.T) {
			decrypted, err := DecryptGCM(encrypted, passphrase)
			if err != nil {
				t.Fatalf("DecryptGCM failed: %v", err)
			}
			if string(result) != decrypted {
				t.Errorf("GCM decryption failed: expected %q, got %q", string(result), decrypted)
			}
		}
	}

	testDecryptLegacy := func(encrypted string, passphrase string, result []byte) func(t *testing.T) {
		return func(t *testing.T) {
			decrypted, err := DecryptLegacy(encrypted, passphrase)
			if err != nil {
				t.Fatalf("DecryptLegacy failed: %v", err)
			}
			if string(result) != decrypted {
				t.Errorf("Legacy decryption failed: expected %q, got %q", string(result), decrypted)
			}
		}
	}

	// Load and run dynamic tests
	// Plaintext tests
	testKey := "plaintext"
	for idx, testCase := range testData.Testdata.Plaintext {
		testCaseBytes := []byte(testCase)
		addTest(
			"test_0_"+testKey+"_encrypt_cbc_not_empty_"+fmt.Sprintf("%d", idx),
			testEncryptCBCNotEmpty(testCaseBytes),
		)
		addTest(
			"test_0_"+testKey+"_encrypt_gcm_not_empty_"+fmt.Sprintf("%d", idx),
			testEncryptGCMNotEmpty(testCaseBytes),
		)
		addTest(
			"test_0_"+testKey+"_encrypt_legacy_not_empty_"+fmt.Sprintf("%d", idx),
			testEncryptLegacyNotEmpty(testCaseBytes),
		)
		addTest(
			"test_1_"+testKey+"_encrypt_decrypt_cbc_"+fmt.Sprintf("%d", idx),
			testEncryptDecryptCBC(testCaseBytes),
		)
		addTest(
			"test_1_"+testKey+"_encrypt_decrypt_gcm_"+fmt.Sprintf("%d", idx),
			testEncryptDecryptGCM(testCaseBytes),
		)
		addTest(
			"test_1_"+testKey+"_encrypt_decrypt_legacy_"+fmt.Sprintf("%d", idx),
			testEncryptDecryptLegacy(testCaseBytes),
		)
	}

	// Hex tests
	testKey = "hex"
	for idx, testCase := range testData.Testdata.Hex {
		testText, err := hexToBytes(testCase)
		if err != nil {
			t.Fatalf("Failed to decode hex string: %v", err)
		}
		addTest(
			"test_2_"+testKey+"_encrypt_cbc_not_empty_"+fmt.Sprintf("%d", idx),
			testEncryptCBCNotEmpty(testText),
		)
		addTest(
			"test_2_"+testKey+"_encrypt_gcm_not_empty_"+fmt.Sprintf("%d", idx),
			testEncryptGCMNotEmpty(testText),
		)
		addTest(
			"test_2_"+testKey+"_encrypt_legacy_not_empty_"+fmt.Sprintf("%d", idx),
			testEncryptLegacyNotEmpty(testText),
		)
		addTest(
			"test_3_"+testKey+"_encrypt_decrypt_cbc_"+fmt.Sprintf("%d", idx),
			testEncryptDecryptCBC(testText),
		)
		addTest(
			"test_3_"+testKey+"_encrypt_decrypt_gcm_"+fmt.Sprintf("%d", idx),
			testEncryptDecryptGCM(testText),
		)
		addTest(
			"test_3_"+testKey+"_encrypt_decrypt_legacy_"+fmt.Sprintf("%d", idx),
			testEncryptDecryptLegacy(testText),
		)
	}

	// Decrypt tests
	for idx, testCase := range testData.Decrypt {
		testKey := testCase.ID
		if testKey == "" {
			testKey = "case_" + string(rune(idx))
		}
		var plaintext []byte
		if testCase.Plaintext != "" {
			plaintext = []byte(testCase.Plaintext)
		} else if testCase.Hex != "" {
			var err error
			plaintext, err = hexToBytes(testCase.Hex)
			if err != nil {
				t.Fatalf("Failed to decode hex string: %v", err)
			}
		} else {
			continue
		}

		passphrase := testCase.Passphrase

		if testCase.EncryptedCBC != "" {
			addTest(
				"test_9_decrypt_cbc_"+testKey,
				testDecryptCBC(testCase.EncryptedCBC, passphrase, plaintext),
			)
		}
		if testCase.EncryptedGCM != "" {
			addTest(
				"test_9_decrypt_gcm_"+testKey,
				testDecryptGCM(testCase.EncryptedGCM, passphrase, plaintext),
			)
		}
		if testCase.EncryptedLegacy != "" {
			addTest(
				"test_9_decrypt_legacy_"+testKey,
				testDecryptLegacy(testCase.EncryptedLegacy, passphrase, plaintext),
			)
		}
	}
}

func hexToBytes(s string) ([]byte, error) {
	b := make([]byte, len(s)/2)
	_, err := fromHex(b, s)
	if err != nil {
		return nil, err
	}
	return b, nil
}
