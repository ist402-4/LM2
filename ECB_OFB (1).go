package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

var (
	// Random bytes
	bytes = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 5}

	// This should be in an env file in production
	MySecret = "abc&1*~#^2^#s0^=)^^7%b34"
)

// Base64 encoding
func Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// Base64 decoding
func Decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

// PKCS7 padding
//Kept running into unicode errors
func PKCS7Pad(text []byte, blockSize int) []byte {
	padding := blockSize - (len(text) % blockSize)
	padText := make([]byte, len(text)+padding)
	copy(padText, text)
	for i := len(text); i < len(padText); i++ {
		padText[i] = byte(padding)
	}
	return padText
}

// Encrypt method is used to encrypt or hide any classified text using ECB mode
func EncryptECB(text, MySecret string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}

	plaintext := []byte(text)
	// Perform PKCS7 padding
	paddedText := PKCS7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(paddedText))

	// Encrypt each block of plaintext using ECB mode
	for len(paddedText) > 0 {
		block.Encrypt(ciphertext, paddedText)
		paddedText = paddedText[aes.BlockSize:]
	}

	return Encode(ciphertext), nil
}

// Decrypt method is used to extract the original text from the encrypted text using ECB mode
func DecryptECB(text, MySecret string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}

	ciphertext := Decode(text)
	plaintext := make([]byte, len(ciphertext))

	// Decrypt each block of ciphertext using ECB mode
	for len(ciphertext) > 0 {
		block.Decrypt(plaintext, ciphertext)
		ciphertext = ciphertext[aes.BlockSize:]
	}

	// Remove PKCS7 padding
	padding := int(plaintext[len(plaintext)-1])
	return string(plaintext[:len(plaintext)-padding]), nil
}

// Encrypt method is used to encrypt or hide any classified text using OFB mode
func EncryptOFB(text, MySecret string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}

	plaintext := []byte(text)
	// Perform PKCS7
	paddedText := PKCS7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(paddedText))

	// Create OFB cipher stream
	ofb := cipher.NewOFB(block, bytes)
	ofb.XORKeyStream(ciphertext, paddedText)

	return Encode(ciphertext), nil
}

// Decrypt method is used to extract the original text from the encrypted text using OFB mode
func DecryptOFB(text, MySecret string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}

	ciphertext := Decode(text)
	plaintext := make([]byte, len(ciphertext))

	// Create OFB cipher stream
	ofb := cipher.NewOFB(block, bytes)
	ofb.XORKeyStream(plaintext, ciphertext)

	// Remove padding
	padding := int(plaintext[len(plaintext)-1])
	return string(plaintext[:len(plaintext)-padding]), nil
}

func main() {
	fmt.Println("Enter the string to encrypt:")
	var StringToEncrypt string
	fmt.Scanln(&StringToEncrypt)

	// Encrypt using ECB mode
	encTextECB, err := EncryptECB(StringToEncrypt, MySecret)
	if err != nil {
		fmt.Println("Error encrypting your classified text using ECB mode:", err)
		return
	}
	fmt.Println("Encrypted text (ECB mode):", encTextECB)

	// Decrypt using ECB mode
	decTextECB, err := DecryptECB(encTextECB, MySecret)
	if err != nil {
		fmt.Println("Error decrypting your encrypted text using ECB mode:", err)
		return
	}
	fmt.Println("Decrypted text (ECB mode):", decTextECB)

	// Encrypt using OFB mode
	encTextOFB, err := EncryptOFB(StringToEncrypt, MySecret)
	if err != nil {
		fmt.Println("Error encrypting your classified text using OFB mode:", err)
		return
	}
	fmt.Println("Encrypted text (OFB mode):", encTextOFB)

	// Decrypt using OFB mode
	decTextOFB, err := DecryptOFB(encTextOFB, MySecret)
	if err != nil {
		fmt.Println("Error decrypting your encrypted text using OFB mode:", err)
		return
	}
	fmt.Println("Decrypted text (OFB mode):", decTextOFB)
}
