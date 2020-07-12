package main

import (
	"fmt"
	"log"
	"os"

	"example.com/cryptogo/crypto"
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
				Name:  "encrypt",
				Usage: "Encrypt message with RSA",
				Action: func(c *cli.Context) error {
					keyName := c.Args().Get(0)
					message := c.Args().Get(1)

					publicKey := crypto.GetPublicKeyFromPem(keyName)

					fmt.Println(crypto.Encrypt(message, publicKey))

					return nil
				},
			},
			{
				Name:  "decrypt",
				Usage: "Decrypt message with RSA",
				Action: func(c *cli.Context) error {
					keyName := c.Args().Get(0)
					encryptedMessage := c.Args().Get(1)

					privateKey := crypto.GetPrivateKeyFromPem(keyName)

					fmt.Println(crypto.Decrypt(encryptedMessage, privateKey))

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
