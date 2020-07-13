package crypto

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
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

// GetPrivateKeyFromPem - Get private key from pem file
func GetPrivateKeyFromPem(keyName string) *rsa.PrivateKey {
	data := getKeyFromPem(keyName)

	// Get private key
	privateKey, err := x509.ParsePKCS1PrivateKey(data.Bytes)

	if err != nil {
		log.Fatalf("Error getting private key - %s", err)
	}

	return privateKey
}

// GetPublicKeyFromPem - Get public key from pem file
func GetPublicKeyFromPem(keyName string) *rsa.PublicKey {
	data := getKeyFromPem(keyName)

	// Get public key
	key, err := x509.ParsePKCS1PublicKey(data.Bytes)

	if err != nil {
		log.Fatalf("Error getting public key - %s", err)
	}

	return key
}

// Encrypt - Encrypt a message
func Encrypt(message string, publicKey *rsa.PublicKey) string {
	messageBytes := []byte(message)
	label := []byte("")
	hash := sha256.New()

	ciphertext, err := rsa.EncryptOAEP(
		hash,
		rand.Reader,
		publicKey, // external
		messageBytes,
		label,
	)

	if err != nil {
		log.Fatalf("Error encrypting message - %s", err)
	}

	encrypted := base64.StdEncoding.EncodeToString(ciphertext)

	return encrypted
}

// Decrypt - Decrypt a message
func Decrypt(encryptedMessage string, privateKey *rsa.PrivateKey) string {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedMessage)

	if err != nil {
		log.Fatalf("Error decoding message to base64 - %s", err)
	}

	label := []byte("")
	hash := sha256.New()

	messageBytes, err := rsa.DecryptOAEP(
		hash,
		rand.Reader,
		privateKey, // internal
		ciphertext,
		label,
	)

	if err != nil {
		log.Fatalf("Erro decrypting message - %s", err)
	}

	return string(messageBytes)
}

func getKeyFromPem(keyName string) *pem.Block {
	pemFile, err := os.Open("crypto/pem/" + keyName + ".pem")

	defer pemFile.Close()

	if err != nil {
		log.Fatalf("Erro opening pem file - %s", err)
	}

	// Get pem file info
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

	return data
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
