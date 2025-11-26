package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/pbkdf2"
)

// Constants provided from exercise document
const (
	b64CipherText = "4Mjg0w+aI8ZkCOH+zH/mPNXkXxs93dzmER99a42bOP1MMRN7FNE3VgvLLQYD1/qNTEsxlTvgAiWMbT4G2IXzHYZynCHZciFdYP6ucbtlZt8="
	passphrase    = "codingexercise"
)

// Payload struct defined from Step 2
type Payload struct {
	DecodedText string `json:"decoded string"`
}

// Main function to show steps functionality.
func main() {
	// 1. Decrypt
	decodedText, err := DecryptAES256(b64CipherText, passphrase)
	if err != nil {
		log.Fatalf("Step 1 Failed: %v", err.Error())
	}
	fmt.Printf("Step 1 Decrypted: %s\n", decodedText)

	// 2. Create JSON
	jsonPayloadBytes, err := CreatePayloadJson(decodedText)
	if err != nil {
		log.Fatalf("Step 2 Failed: %v", err.Error())
	}
	fmt.Printf("Step 2 JSON: %s\n", string(jsonPayloadBytes))

	// 3. Hash the JSON
	decodedJsonHash := GenerateSHA256Hash(jsonPayloadBytes)
	fmt.Printf("Step 3 Hash: %s\n", decodedJsonHash)

	// 3a. Create JWT from JSON
	jwt, err := CreateJwtFromJson(jsonPayloadBytes, passphrase)
	if err != nil {
		log.Fatalf("Step 3a Failed: %v", err.Error())
	}
	fmt.Printf("Step 3a JWT: %s\n", jwt)
}

// Step 1:
func DecryptAES256(b64Cipher string, passphrase string) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(b64Cipher)
	if err != nil {
		return "", err
	}

	if len(cipherText) < 32 {
		return "", fmt.Errorf("ciphertext too short")
	}

	salt := cipherText[:16]
	iv := cipherText[16:32]
	encryptedData := cipherText[32:]

	// Key derivation using variables provided in the exercise document
	key := pbkdf2.Key([]byte(passphrase), salt, 100000, 32, sha1.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(encryptedData, encryptedData)

	return unpadDecryptedData(encryptedData)
}

// Note: In production, use a robust unpadding function with error checking
func unpadDecryptedData(encryptedData []byte) (string, error) {
	length := len(encryptedData)
	if length == 0 {
		return "", fmt.Errorf("empty data")
	}
	padLen := int(encryptedData[length-1])
	if padLen > length || padLen == 0 {
		return "", fmt.Errorf("invalid padding")
	}

	return string(encryptedData[:length-padLen]), nil
}

// Step 2: Create JSON object of Payload
// Note: Normally this would not be a helper func but creating it up for easy marking.
func CreatePayloadJson(decodedText string) ([]byte, error) {
	payload := Payload{DecodedText: decodedText}
	return json.Marshal(payload)
}

// Step 3: Generate SHA256 hash of JSON bytes
// Note: was confusing why we never use this.
func GenerateSHA256Hash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Step 3a: Add HMAC function to create JWT from JSON using passphrase
func CreateJwtFromJson(jsonPayload []byte, passphrase string) (string, error) {
	var claims jwt.MapClaims
	// Unmarshal the JSON back into a map to use as JWT claims
	if err := json.Unmarshal(jsonPayload, &claims); err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(passphrase))
}
