package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	// Hardcoded codebook (key)
	codebook := "0123456789abcdef0123456789abcdef"

	// plaintext from user
	fmt.Print("Enter plaintext: ")
	var plaintext string
	fmt.Scanln(&plaintext)

	// ECB encryption
	encryptedECB, err := encryptECB(plaintext, codebook)
	if err != nil {
		fmt.Println("Error during ECB encryption:", err)
		os.Exit(1)
	}
	fmt.Println("ECB Encryption:")
	fmt.Println("Plaintext:", plaintext)
	fmt.Println("Encrypted Text:", encryptedECB)

	// Perform OFB encryption
	encryptedOFB, err := encryptOFB(plaintext, codebook)
	if err != nil {
		fmt.Println("Error during OFB encryption:", err)
		os.Exit(1)
	}
	fmt.Println("\nOFB Encryption:")
	fmt.Println("Plaintext:", plaintext)
	fmt.Println("Encrypted Text:", encryptedOFB)
}

// encryptECB performs ECB encryption on the plaintext using the codebook.
func encryptECB(plaintext, codebook string) (string, error) {
	// Create a new AES cipher block using the codebook
	block, err := aes.NewCipher([]byte(codebook))
	if err != nil {
		return "", err
	}

	// Pad the plaintext to the block size
	paddedPlaintext := padPlaintext(plaintext, block.BlockSize())

	// Create a byte slice to hold the encrypted text
	encryptedText := make([]byte, len(paddedPlaintext))

	// Encrypt each block of plaintext using ECB mode
	blockSize := block.BlockSize()
	for i := 0; i < len(paddedPlaintext); i += blockSize {
		block.Encrypt(encryptedText[i:i+blockSize], []byte(paddedPlaintext[i:i+blockSize]))
	}

	// Convert the encrypted text to hexadecimal representation
	return hex.EncodeToString(encryptedText), nil
}

func encryptOFB(plaintext, codebook string) (string, error) {
	block, err := aes.NewCipher([]byte(codebook))
	if err != nil {
		return "", err
	}

	// Generate an initialization vector (IV) for OFB mode
	iv := make([]byte, aes.BlockSize)

	// Create a new OFB stream cipher using the block and IV
	stream := cipher.NewOFB(block, iv)

	// Create a byte slice to hold the encrypted ciphertext
	ciphertext := make([]byte, len(plaintext))

	// Encrypt plaintext using the OFB stream cipher
	stream.XORKeyStream(ciphertext, []byte(plaintext))

	// Convert ciphertext to hexadecimal representation
	return hex.EncodeToString(ciphertext), nil
}

func padPlaintext(plaintext string, blockSize int) string {
	padding := blockSize - len(plaintext)%blockSize
	padText := []byte(plaintext)
	for i := 0; i < padding; i++ {
		padText = append(padText, byte(padding))
	}
	return string(padText)
}
