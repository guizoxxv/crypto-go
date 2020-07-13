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

func Generate(limit int) {
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

func EncryptCsv(file string, publicKey *rsa.PublicKey) {
	timeStart := time.Now()

	inputFile, err := os.Open("fileprocesser/files/" + file + ".csv")

	defer inputFile.Close()

	if err != nil {
		log.Fatalf("Error openning csv file")
	}

	outputFile, err := os.Create("fileprocesser/files/" + file + "_encrypted.csv")

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
			line[i] = crypto.Encrypt(line[i], publicKey)
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

func DecryptCsv(file string, privateKey *rsa.PrivateKey) {
	timeStart := time.Now()

	inputFile, err := os.Open("fileprocesser/files/" + file + "_encrypted.csv")

	defer inputFile.Close()

	if err != nil {
		log.Fatalf("Error openning csv file")
	}

	outputFile, err := os.Create("fileprocesser/files/" + file + "_decrypted.csv")

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
			line[i] = crypto.Decrypt(line[i], privateKey)
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
