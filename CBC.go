package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

var bytes = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}

const MySecret string = "abc&1*~#^2^#s0^=)^^7%b34"

func Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func Decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

// from Xavier's code
func PKCS7Pad(text []byte, blockSize int) []byte {
	padding := blockSize - (len(text) % blockSize)
	padText := make([]byte, len(text)+padding)
	copy(padText, text)
	for i := len(text); i < len(padText); i++ {
		padText[i] = byte(padding)
	}
	return padText
}

func Encrypt(text, MySecret string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}

	plainText := []byte(text)
	padText := PKCS7Pad(plainText, aes.BlockSize)

	// Create a new AES block mode cipher in CBC mode
	cipherText := make([]byte, len(padText))
	iv := bytes
	// Uses block mode instead of XORstream (from https://pkg.go.dev/crypto/cipher#NewCBCEncrypter)
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(cipherText, padText) //https://pkg.go.dev/crypto/cipher#BlockMode.CryptBlocks

	return Encode(cipherText), nil
}

func Decrypt(text, MySecret string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}

	cipherText := Decode(text)

	// Create a new AES block mode cipher in CBC mode
	plainText := make([]byte, len(cipherText))
	iv := bytes
	// Used block mode instead of XORstream (from https://pkg.go.dev/crypto/cipher#NewCBCDecrypter)
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(plainText, cipherText) //https://pkg.go.dev/crypto/cipher#BlockMode.CryptBlocks
	// Remove padding
	padding := int(plainText[len(plainText)-1])
	return string(plainText[:len(plainText)-padding]), nil
}

func main() {
	fmt.Println("Enter the string to encrypt:")
	var StringToEncrypt string
	fmt.Scanln(&StringToEncrypt)

	encText, err := Encrypt(StringToEncrypt, MySecret)
	if err != nil {
		fmt.Println("Error encrypting your text:", err)
		return
	}

	fmt.Println("Encrypted text:", encText)

	decText, err := Decrypt(encText, MySecret)
	if err != nil {
		fmt.Println("Error decrypting the encrypted text:", err)
		return
	}

	fmt.Println("Decrypted text:", decText)
}
