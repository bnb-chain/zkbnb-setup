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
			/* --------------------------------- Phase 1 Initialize -------------------------------- */
			{
				Name:        "p1n",
				Usage:       "p1n <power> <outputPath>",
				Description: "initialize phase 1 of parameters generation for Groth16",
				Action:      p1n,
			},

			/* --------------------------------- Phase 1 Contribute -------------------------------- */
			{
				Name:        "p1c",
				Usage:       "p1c <inputPath> <outputPath>",
				Description: "contribute phase 1 randomness for Groth16",
				Action:      p1c,
			},
			/* --------------------------------- Phase 1 Verify -------------------------------- */
			{
				Name:        "p1v",
				Usage:       "p1v <inputPath>",
				Description: "verify phase 1 contributions for Groth16",
				Action:      p1v,
			},
			/* --------------------------------- Phase 2 Initialize -------------------------------- */
			{
				Name:        "p2n",
				Usage:       "p2n <inputPhase1Path> <inputR1CS> <outputPhase2> <evaluations>",
				Description: "initialize phase 2 for the given circuit",
				Action:      p2n,
			},

			/* --------------------------------- Phase 2 Contribute -------------------------------- */
			{
				Name:        "p2c",
				Usage:       "p2c <inputPath> <outputPath>",
				Description: "contribute phase 2 randomness for Groth16",
				Action:      p2c,
			},
			/* --------------------------------- Phase 2 Verify -------------------------------- */
			{
				Name:        "p2v",
				Usage:       "p2v <inputPath>",
				Description: "verify phase 2 contributions for Groth16",
				Action:      p2v,
			},
			/* --------------------------------- Keys Extraction -------------------------------- */
			{
				Name:        "keys",
				Usage:       "keys <inputPath> <evaluations>",
				Description: "extract proving and verifying keys",
				Action:      extract,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
