package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <path-to-encrypted-key-file> <password>", os.Args[0])
	}

	encryptedFilePath := os.Args[1]
	password := []byte(os.Args[2])

	// Step 1: Read the encrypted file content
	encryptedFileContent, err := os.ReadFile(encryptedFilePath)
	if err != nil {
		log.Fatalf("Error reading encrypted file: %v", err)
	}

	// Step 2: Extract base64-encoded data from the PEM-like format
	encodedData := extractBase64Data(string(encryptedFileContent))
	if encodedData == "" {
		log.Fatalf("Error extracting base64 data from file")
	}

	// Step 3: Decode the base64 data to get the encrypted binary data
	encryptedData, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		log.Fatalf("Error decoding base64 data: %v", err)
	}

	// Step 4: Decrypt the private key
	decryptedKey, err := encrypted.Decrypt(encryptedData, password)
	if err != nil {
		log.Fatalf("Error decrypting private key: %v", err)
	}

	// Step 5: Parse the decrypted key with PKCS8
	key, err := x509.ParsePKCS8PrivateKey(decryptedKey)
	if err != nil {
		log.Fatalf("error in ParsePKCS8PrivateKey: %v", err)
	}
	// Step 5: Output the unencrypted private key
	// try to convert key to *rsa.PrivateKey
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		log.Fatal("not an RSA key") // TODO: handle EC keys etc.
	}
	// Marshal the private key to ASN.1 DER encoded form
	derKey := x509.MarshalPKCS1PrivateKey(rsaKey)
	// Create a PEM block with the private key
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derKey,
	}

	// Encode the PEM block to a string
	pemString := string(pem.EncodeToMemory(pemBlock))
	fmt.Print(pemString)
}

// extractBase64Data extracts base64-encoded data from a PEM-like file format
func extractBase64Data(pemData string) string {
	var buffer bytes.Buffer
	inData := false
	for _, line := range strings.Split(pemData, "\n") {
		if strings.HasPrefix(line, "-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----") {
			inData = true
			continue
		}
		if strings.HasPrefix(line, "-----END ENCRYPTED SIGSTORE PRIVATE KEY-----") {
			break
		}
		if inData {
			buffer.WriteString(line)
		}
	}
	return buffer.String()
}
