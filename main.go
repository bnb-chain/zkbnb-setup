package main

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name: "gnark-setup",
		Usage: "Use this tool to generate parameters of Groth16 via MPC",
		UsageText: "gnark-setup command subcommand [arguments...]",
		Commands: []*cli.Command{
			/* --------------------------------- Phase 1 -------------------------------- */
			{
				Name:    "phase1",
				Aliases: []string{"p1"},
				Usage:   "phase one commands",
				Subcommands: []*cli.Command{
					{
						/* --------------------------- Phase 1 Initialize --------------------------- */
						Name:  "init",
						Usage: "init <power> <output>",
						Description: "initialize the first phase of parameters generation for Groth16",
						Aliases: []string{"i"},
						Action: func(cCtx *cli.Context) error {
							if cCtx.Args().Len() != 2 {
								fmt.Println("incorrect number of arguments to phase1 init")
								return nil
							}
							powerStr := cCtx.Args().Get(0)
							power, err := strconv.Atoi(powerStr)
							if err != nil {
								fmt.Printf("failed to convert power %s to an integer\n", powerStr)
								return nil
							}
							outputPath := cCtx.Args().Get(1)
							output, err := os.Create(outputPath)
							if err != nil {
								fmt.Printf("failed to create %s\n", outputPath)
								return nil
							}
							defer output.Close()
							// TODO: call phase1Initialize
							fmt.Printf("Initializing with power %d and output %s \n", power, outputPath)
							return nil
						},
					},
					{
						/* --------------------------- Phase 1 Contribute --------------------------- */
						Name:  "contribute",
						Usage: "contribute <challenge> <response>",
						Aliases: []string{"c"},
						Action: func(cCtx *cli.Context) error {
							if cCtx.Args().Len() != 2 {
								fmt.Println("incorrect number of arguments to contribute")
								return nil
							}
							challengePath := cCtx.Args().Get(0)
							responsePath := cCtx.Args().Get(1)
							challenge, err := os.Open(challengePath)
							if err != nil {
								fmt.Printf("failed to open %s\n", challengePath)
								return nil
							}
							defer challenge.Close()
							response, err := os.Create(responsePath)
							if err != nil {
								fmt.Printf("failed to create %s\n", responsePath)
								return nil
							}
							defer response.Close()
							// TODO: phase2 contribute
							fmt.Printf("phase 2 contribute based on challenge %s to a response %s\n", challengePath, responsePath)
							return nil
						},
					},
					{
						/* ----------------------------- Phase 1 Verify ----------------------------- */
						Name:  "verify",
						Usage: "verify <response> <challenge>",
						Aliases: []string{"v"},
						Action: func(cCtx *cli.Context) error {
							if cCtx.Args().Len() != 2 {
								fmt.Println("incorrect number of arguments to verify")
								return nil
							}
							responsePath := cCtx.Args().Get(0)
							challengePath := cCtx.Args().Get(1)
							challenge, err := os.Open(challengePath)
							if err != nil {
								fmt.Printf("failed to open %s\n", challengePath)
								return nil
							}
							defer challenge.Close()
							response, err := os.Open(responsePath)
							if err != nil {
								fmt.Printf("failed to open %s\n", responsePath)
								return nil
							}
							defer response.Close()
							// TODO: phase2 verify
							fmt.Printf("phase 2 verify response %s based on challenge %s\n", responsePath, challengePath)
							return nil
						},
					},
				},
			},
			/* --------------------------------- Phase 2 -------------------------------- */
			{
				Name:    "phase2",
				Aliases: []string{"p2"},
				Usage:   "phase two commands",
				Subcommands: []*cli.Command{
					{
						/* --------------------------- Phase 2 Initialize --------------------------- */
						Name:  "init",
						Usage: "init <phase1Output> <r1csFile> <phase2Output>",
						Description: "initialize the second phase of parameters generation for Groth16",
						Aliases: []string{"i"},
						Action: func(cCtx *cli.Context) error {
							if cCtx.Args().Len() != 3 {
								fmt.Println("incorrect number of arguments to phase2 init")
								return nil
							}
							phase1Path := cCtx.Args().Get(0)
							r1csPath := cCtx.Args().Get(1)
							phase2Path := cCtx.Args().Get(2)
							phase1File, err := os.Open(phase1Path)
							if err != nil {
								fmt.Printf("failed to open %s\n", phase1Path)
								return nil
							}
							defer phase1File.Close()
							r1csFile, err := os.Create(r1csPath)
							if err != nil {
								fmt.Printf("failed to create %s\n", r1csPath)
								return nil
							}
							defer r1csFile.Close()
							phase2File, err := os.Create(phase2Path)
							if err != nil {
								fmt.Printf("failed to create %s\n", phase2Path)
								return nil
							}
							defer phase2File.Close()
							
							// TODO: call phase2 prepare
							fmt.Printf("Initializing phase2")
							return nil
						},
					},
					{
						/* --------------------------- Phase 2 Contribute --------------------------- */
						Name:  "contribute",
						Usage: "contribute <challenge> <response>",
						Aliases: []string{"c"},
						Action: func(cCtx *cli.Context) error {
							if cCtx.Args().Len() != 2 {
								fmt.Println("incorrect number of arguments to contribute")
								return nil
							}
							challengePath := cCtx.Args().Get(0)
							responsePath := cCtx.Args().Get(1)
							challenge, err := os.Open(challengePath)
							if err != nil {
								fmt.Printf("failed to open %s\n", challengePath)
								return nil
							}
							defer challenge.Close()
							response, err := os.Create(responsePath)
							if err != nil {
								fmt.Printf("failed to create %s\n", responsePath)
								return nil
							}
							defer response.Close()
							// TODO: phase1 contribute
							fmt.Printf("phase 1 contribute based on challenge %s to a response %s\n", challengePath, responsePath)
							return nil
						},
					},
					{
						/* ----------------------------- Phase 2 Verify ----------------------------- */
						Name:  "verify",
						Usage: "verify <response> <challenge>",
						Aliases: []string{"v"},
						Action: func(cCtx *cli.Context) error {
							if cCtx.Args().Len() != 2 {
								fmt.Println("incorrect number of arguments to verify")
								return nil
							}
							responsePath := cCtx.Args().Get(0)
							challengePath := cCtx.Args().Get(1)
							challenge, err := os.Open(challengePath)
							if err != nil {
								fmt.Printf("failed to open %s\n", challengePath)
								return nil
							}
							defer challenge.Close()
							response, err := os.Open(responsePath)
							if err != nil {
								fmt.Printf("failed to open %s\n", responsePath)
								return nil
							}
							defer response.Close()
							// TODO: phase1 verify
							fmt.Printf("phase 1 verify response %s based on challenge %s\n", responsePath, challengePath)
							return nil
						},
					},
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}