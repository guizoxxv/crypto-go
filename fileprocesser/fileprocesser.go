package fileprocesser

import (
	"bufio"
	"crypto/rsa"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"strconv"
	"time"

	"example.com/cryptogo/crypto"
)

// GenerateCsv - Generate a csv file with random data
func GenerateCsv(limit int) {
	file, err := os.Create("fileprocesser/files/data.csv")

	defer file.Close()

	if err != nil {
		log.Fatalf("Error creating csv file - %s", err)
	}

	writer := csv.NewWriter(file)

	defer writer.Flush()

	for i := 1; i <= limit; i++ {
		index := strconv.Itoa(i)

		name := "User " + index
		email := "user" + index + "@example.com"
		age := strconv.Itoa(rand.Intn(100-1) + 1)

		err := writer.Write([]string{name, email, age})

		if err != nil {
			log.Fatalf("Error writing to csv file - %s", err)
		}

		fmt.Printf("Line %d processed\n", i)
	}
}

// EncryptCsvRSA - Encrypt csv file with RSA
func EncryptCsvRSA(publicKey *rsa.PublicKey) {
	timeStart := time.Now()

	inputFile, err := os.Open("fileprocesser/files/data.csv")

	defer inputFile.Close()

	if err != nil {
		log.Fatalf("Error openning csv file")
	}

	outputFile, err := os.Create("fileprocesser/files/data_rsa_encrypted.csv")

	defer outputFile.Close()

	if err != nil {
		log.Fatalf("Error creating csv file - %s", err)
	}

	reader := csv.NewReader(bufio.NewReader(inputFile))
	writer := csv.NewWriter(outputFile)

	defer writer.Flush()

	lineNumber := 1

	for {
		line, err := reader.Read()

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Fatal(err)
		}

		for i := range line {
			line[i] = crypto.EncryptRSA(line[i], publicKey)
		}

		err = writer.Write(line)

		if err != nil {
			log.Fatalf("Error writing to csv file - %s", err)
		}

		fmt.Printf("Line %d processed\n", lineNumber)

		lineNumber++
	}

	duration := time.Now().Sub(timeStart).Seconds()

	fmt.Printf("Duration: %.2f s", duration)
}

// DecryptCsvRSA - Decrypt a csv file with RSA
func DecryptCsvRSA(privateKey *rsa.PrivateKey) {
	timeStart := time.Now()

	inputFile, err := os.Open("fileprocesser/files/data_rsa_encrypted.csv")

	defer inputFile.Close()

	if err != nil {
		log.Fatalf("Error openning csv file")
	}

	outputFile, err := os.Create("fileprocesser/files/data_rsa_decrypted.csv")

	defer outputFile.Close()

	if err != nil {
		log.Fatalf("Error creating csv file - %s", err)
	}

	reader := csv.NewReader(bufio.NewReader(inputFile))
	writer := csv.NewWriter(outputFile)

	defer writer.Flush()

	lineNumber := 1

	for {
		line, err := reader.Read()

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Fatal(err)
		}

		for i := range line {
			line[i] = crypto.DecryptRSA(line[i], privateKey)
		}

		err = writer.Write(line)

		if err != nil {
			log.Fatalf("Error writing to csv file - %s", err)
		}

		fmt.Printf("Line %d processed\n", lineNumber)

		lineNumber++
	}

	duration := time.Now().Sub(timeStart).Seconds()

	fmt.Printf("Duration: %.2f s", duration)
}

// EncryptCsvAES - Encrypt csv file with AES
func EncryptCsvAES(key string) {
	timeStart := time.Now()

	inputFile, err := os.Open("fileprocesser/files/data.csv")

	defer inputFile.Close()

	if err != nil {
		log.Fatalf("Error openning csv file")
	}

	outputFile, err := os.Create("fileprocesser/files/data_aes_encrypted.csv")

	defer outputFile.Close()

	if err != nil {
		log.Fatalf("Error creating csv file - %s", err)
	}

	reader := csv.NewReader(bufio.NewReader(inputFile))
	writer := csv.NewWriter(outputFile)

	defer writer.Flush()

	lineNumber := 1

	for {
		line, err := reader.Read()

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Fatal(err)
		}

		for i := range line {
			line[i] = crypto.EncryptAES(line[i], key)
		}

		err = writer.Write(line)

		if err != nil {
			log.Fatalf("Error writing to csv file - %s", err)
		}

		fmt.Printf("Line %d processed\n", lineNumber)

		lineNumber++
	}

	duration := time.Now().Sub(timeStart).Seconds()

	fmt.Printf("Duration: %.2f s", duration)
}

// DecryptCsvAES - Decrypt a csv file with AES
func DecryptCsvAES(key string) {
	timeStart := time.Now()

	inputFile, err := os.Open("fileprocesser/files/data_aes_encrypted.csv")

	defer inputFile.Close()

	if err != nil {
		log.Fatalf("Error openning csv file")
	}

	outputFile, err := os.Create("fileprocesser/files/data_aes_decrypted.csv")

	defer outputFile.Close()

	if err != nil {
		log.Fatalf("Error creating csv file - %s", err)
	}

	reader := csv.NewReader(bufio.NewReader(inputFile))
	writer := csv.NewWriter(outputFile)

	defer writer.Flush()

	lineNumber := 1

	for {
		line, err := reader.Read()

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Fatal(err)
		}

		for i := range line {
			line[i] = crypto.DecryptAES(line[i], key)
		}

		err = writer.Write(line)

		if err != nil {
			log.Fatalf("Error writing to csv file - %s", err)
		}

		fmt.Printf("Line %d processed\n", lineNumber)

		lineNumber++
	}

	duration := time.Now().Sub(timeStart).Seconds()

	fmt.Printf("Duration: %.2f s", duration)
}
