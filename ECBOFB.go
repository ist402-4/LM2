package main

import "fmt"

var Codebook = [4][2]int{{0b00, 0b01}, {0b01, 0b10}, {0b10, 0b11}, {0b11, 0b00}}
var message = [4]int{0b01, 0b00, 0b10, 0b00} // this is an uppercase H
func codebookLookup(xor int) (lookupValue int) {
	var i, j int = 0, 0
	for i = 0; i < 4; i++ {
		if Codebook[i][j] == xor {
			j++
			lookupValue = Codebook[i][j]
			break
		}
	}
	return lookupValue
}
func codebookLookupByValue(xor int) (lookupValue int) {
	var i, j int = 0, 1
	for i = 0; i < 4; i++ {
		if Codebook[i][j] == xor {
			lookupValue = Codebook[i][j-1]
			break
		}
	}
	return lookupValue
}
func main() {
	var lookupValue int = 0
	var Cipher = [4]int{}
	fmt.Println("----------------------------------------------------")
	fmt.Println("ECB Encryption and Decryption")
	fmt.Println("----------------------------------------------------")

	for i := 0; i < 4; i++ {
		fmt.Printf("The plaintext value of a is %02b\n", message[i])
	}
	for i := 0; i < 4; i++ {
		lookupValue = codebookLookup(message[i])
		fmt.Printf("The cipher value of a is %02b\n", lookupValue)
		Cipher[i] += lookupValue
	}
	for i := 0; i < 4; i++ {
		lookupValue = codebookLookupByValue(Cipher[i])
		fmt.Printf("The original plaintext value of a is %02b\n", lookupValue)
	}
	fmt.Println("----------------------------------------------------")
	fmt.Println("OFB Encryption and Decryption")
	fmt.Println("----------------------------------------------------")

}
