package crypto

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

// GenerateKeyPair - Generate RSA key pair
func GenerateKeyPair(keyPrefix string) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		log.Fatalf("Error generating key pair - %s", err)
	}

	publicKey := &privateKey.PublicKey

	createPrivatePem(privateKey, keyPrefix+"_private_key")
	createPublicPem(publicKey, keyPrefix+"_public_key")
}

// GetKeysFromPem - Get key pair from pem file
func GetKeysFromPem(keyName string) (*rsa.PrivateKey, *rsa.PublicKey) {
	pemFile, err := os.Open("crypto/pem/" + keyName + ".pem")

	defer pemFile.Close()

	if err != nil {
		log.Fatalf("Erro opening pem file - %s", err)
	}

	// Get private key pem file info
	pemInfo, err := pemFile.Stat()

	if err != nil {
		log.Fatalf("Error getting pem file info - %s", err)
	}

	// Read pem
	pemBytes := make([]byte, pemInfo.Size())
	buffer := bufio.NewReader(pemFile)

	_, err = buffer.Read(pemBytes)

	if err != nil {
		log.Fatalf("Error reading pem - %s", err)
	}

	// Decode buffer
	data, _ := pem.Decode(pemBytes)

	// Get private key
	privateKey, err := x509.ParsePKCS1PrivateKey(data.Bytes)

	if err != nil {
		log.Fatalf("Error getting private key - %s", err)
	}

	publicKey := &privateKey.PublicKey

	return privateKey, publicKey
}

func createPrivatePem(privateKey *rsa.PrivateKey, keyName string) {
	file := createPemFile(keyName)

	defer file.Close()

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	encodePemFile(file, block, keyName)
}

func createPublicPem(publicKey *rsa.PublicKey, keyName string) {
	file := createPemFile(keyName)

	defer file.Close()

	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	}

	encodePemFile(file, block, keyName)
}

func createPemFile(keyName string) *os.File {
	file, err := os.Create("crypto/pem/" + keyName + ".pem")

	if err != nil {
		log.Fatalf("Error creating pem file '%s' - %s", keyName, err)
	}

	return file
}

func encodePemFile(file *os.File, block *pem.Block, keyName string) {
	err := pem.Encode(file, block)

	if err != nil {
		log.Fatalf("Error coding pem file '%s' - %s", keyName, err)
	}

	log.Printf("Pem file created '%s'", keyName)
}
