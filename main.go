package main

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"example.com/cryptogo/crypto"
	"example.com/cryptogo/fileprocesser"
	"github.com/joho/godotenv"
	"github.com/urfave/cli/v2"
)

func main() {
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatalf("Error loading .env - %s", err)
	}

	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:  "test",
				Usage: "Test command",
				Action: func(c *cli.Context) error {
					log.Println("Executing command 'test'")
					fmt.Println("Test")

					return nil
				},
			},
			{
				Name:  "generate-key-pair",
				Usage: "Generate RSA public/private key internal/external key pairs",
				Action: func(c *cli.Context) error {
					crypto.GenerateKeyPair("alice")
					crypto.GenerateKeyPair("bob")

					return nil
				},
			},
			{
				Name:  "encrypt-rsa",
				Usage: "Encrypt message with RSA",
				Action: func(c *cli.Context) error {
					keyName := c.Args().Get(0)
					message := c.Args().Get(1)

					publicKey := crypto.GetPublicKeyFromPem(keyName)

					fmt.Println(crypto.EncryptRSA(message, publicKey))

					return nil
				},
			},
			{
				Name:  "decrypt-rsa",
				Usage: "Decrypt message with RSA",
				Action: func(c *cli.Context) error {
					keyName := c.Args().Get(0)
					encryptedMessage := c.Args().Get(1)

					privateKey := crypto.GetPrivateKeyFromPem(keyName)

					fmt.Println(crypto.DecryptRSA(encryptedMessage, privateKey))

					return nil
				},
			},
			{
				Name:  "encrypt-aes",
				Usage: "Encrypt message with AES",
				Action: func(c *cli.Context) error {
					message := c.Args().Get(0)
					key := crypto.HashKey("password")

					fmt.Println(crypto.EncryptAES(message, key))

					return nil
				},
			},
			{
				Name:  "decrypt-aes",
				Usage: "Decrypt message with AES",
				Action: func(c *cli.Context) error {
					encryptedMessage := c.Args().Get(0)
					key := crypto.HashKey("password")

					fmt.Println(crypto.DecryptAES(encryptedMessage, key))

					return nil
				},
			},
			{
				Name:  "generate-csv",
				Usage: "Generate random csv file",
				Action: func(c *cli.Context) error {
					limitArg := c.Args().Get(0)
					limit, err := strconv.Atoi(limitArg)

					if err != nil {
						log.Fatalf("Invalid limit '%d' - %s", limit, err)
					}

					fileprocesser.Generate(limit)

					return nil
				},
			},
			{
				Name:  "encrypt-csv-rsa",
				Usage: "Encrypt csv file with RSA",
				Action: func(c *cli.Context) error {
					keyName := c.Args().Get(0)
					fileName := c.Args().Get(1)

					publicKey := crypto.GetPublicKeyFromPem(keyName)

					fileprocesser.EncryptCsv(fileName, publicKey)

					return nil
				},
			},
			{
				Name:  "decrypt-csv-rsa",
				Usage: "Decrypt csv file with RSA",
				Action: func(c *cli.Context) error {
					keyName := c.Args().Get(0)
					fileName := c.Args().Get(1)

					privateKey := crypto.GetPrivateKeyFromPem(keyName)

					fileprocesser.DecryptCsv(fileName, privateKey)

					return nil
				},
			},
		},
	}

	err = app.Run(os.Args)

	if err != nil {
		log.Printf("Error executing command - %s", err)

		return
	}
}
