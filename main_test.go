package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testB64CipherText = "4Mjg0w+aI8ZkCOH+zH/mPNXkXxs93dzmER99a42bOP1MMRN7FNE3VgvLLQYD1/qNTEsxlTvgAiWMbT4G2IXzHYZynCHZciFdYP6ucbtlZt8="
	testPassphrase    = "codingexercise"
	testPlaintext     = "Hello, World! This is a test message."
)

func TestDecryptAES256(t *testing.T) {
	tests := []struct {
		name         string
		cipherInput  string
		passInput    string
		wantText     string
		wantErr      bool
		wantErrorMsg string
	}{
		{
			name:        "success",
			cipherInput: testB64CipherText,
			passInput:   testPassphrase,
			wantText:    testPlaintext,
			wantErr:     false,
		},
		{
			name:         "invalid base64 string",
			cipherInput:  "This-is-not-base64!",
			passInput:    testPassphrase,
			wantErr:      true,
			wantErrorMsg: "illegal base64 data",
		},
		{
			name:         "input too short (less than salt+iv)",
			cipherInput:  "SGVsbG8=", // b64 "Hello"
			passInput:    testPassphrase,
			wantErr:      true,
			wantErrorMsg: "ciphertext too short",
		},
		{
			name:         "wrong password (should fail padding check)",
			cipherInput:  testB64CipherText,
			passInput:    "wrong-password",
			wantErr:      true,
			wantErrorMsg: "invalid padding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecryptAES256(tt.cipherInput, tt.passInput)

			if (err != nil) != tt.wantErr {
				t.Fatalf("DecryptAES256() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && tt.wantErrorMsg != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrorMsg) {
					t.Errorf("expected error containing %q, got %v", tt.wantErrorMsg, err)
				}
			}

			if !tt.wantErr && got != tt.wantText {
				t.Errorf("DecryptAES256() = %q, want %q", got, tt.wantText)
			}
		})
	}
}

// Note: this edgecase is not technically reachable via DecryptAES256,
// as the ciphertext length check prevents it.
func TestUnpadDecryptedData_EmptyData_Fail(t *testing.T) {
	_, err := unpadDecryptedData([]byte{})
	if err == nil || !strings.Contains(err.Error(), "empty data") {
		t.Errorf("Expected 'empty data' error, got %v", err)
	}
}

func TestCreateJSONPayload_ValidValue_Success(t *testing.T) {
	wantText := "Test message with !@#$_`~ special chars and numbers 12345."
	gotJson, err := CreatePayloadJson(wantText)

	if err != nil {
		t.Fatalf("CreateJSONPayload failed unexpectedly: %v", err)
	}

	var p Payload
	if err := json.Unmarshal(gotJson, &p); err != nil {
		t.Fatalf("Generated invalid JSON: %v", err)
	}

	if p.DecodedText != wantText {
		t.Errorf("Content mismatch. Got %q, want %q", p.DecodedText, wantText)
	}
}

func TestGenerateSHA256Hash_ValidText_Success(t *testing.T) {
	input := []byte("test data for hashing")
	expectedHash := "f7eb7961d8a233e6256d3a6257548bbb9293c3a08fb3574c88c7d6b429dbb9f5"

	gotHash := GenerateSHA256Hash(input)

	if len(gotHash) != 64 {
		t.Errorf("Hash length incorrect. Got %d, want 64", len(gotHash))
	}

	if gotHash != expectedHash {
		t.Errorf("Hash algorithm failed.\nGot:  %s\nWant: %s", gotHash, expectedHash)
	}
}

func TestGenerateSHA256Hash_EmptyText_Success(t *testing.T) {
	emptyInput := []byte("")
	expectedHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	gotHash := GenerateSHA256Hash(emptyInput)

	if gotHash != expectedHash {
		t.Errorf("Empty input hash failed.\nGot:  %s\nWant: %s", gotHash, expectedHash)
	}
}

func TestCreateJwtFromJson_ValidJson_Success(t *testing.T) {
	jsonString := fmt.Sprintf(`{"decoded_text":"%v"}`, testPlaintext)
	mockPayload := []byte(jsonString)

	gotTokenString, err := CreateJwtFromJson(mockPayload, testPassphrase)
	if err != nil {
		t.Fatalf("Failed to create JWT: %v", err)
	}

	// Validate the generated JWT by parsing it back and checking the signature
	gotToken, err := jwt.Parse(gotTokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(testPassphrase), nil
	})

	if err != nil || !gotToken.Valid {
		t.Fatalf("Generated JWT failed to validate: %v", err)
	}

	// Validate the claims inside the token match the original JSON
	if gotClaims, ok := gotToken.Claims.(jwt.MapClaims); ok {
		if gotClaims["decoded_text"] != testPlaintext {
			t.Errorf("Claim content mismatch. Got %v, want 'final check'", gotClaims["decoded_text"])
		}
	} else {
		t.Error("Unable to extract claims")
	}
}

func TestCreateJwtFromJson_InvalidJson_Fail(t *testing.T) {
	mockPayload := []byte(`not json`)

	_, err := CreateJwtFromJson(mockPayload, testPassphrase)

	if err == nil {
		t.Fatal("Expected error for invalid JSON input, but got nil")
	}
	if !strings.Contains(err.Error(), "invalid character") {
		t.Errorf("Expected JSON unmarshal error, got: %v", err)
	}
}
