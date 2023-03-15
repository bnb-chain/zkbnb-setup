package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:      "setup",
		Usage:     "Use this tool to generate parameters of Groth16 via MPC",
		UsageText: "setup command [arguments...]",
		Commands: []*cli.Command{
			/* --------------------------------- Phase 1 Initialize-------------------------------- */
			{
				Name:        "p1n",
				Usage:       "init <power>",
				Description: "initialize the first phase of parameters generation for Groth16",
				Action:      p1n,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
