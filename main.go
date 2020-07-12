package main

import (
	"fmt"
	"log"
	"os"

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
		},
	}

	err = app.Run(os.Args)

	if err != nil {
		log.Printf("Error executing command - %s", err)

		return
	}
}
