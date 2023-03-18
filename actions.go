package main

import (
	"errors"
	"strconv"

	"github.com/bnbchain/zkbnb-setup/phase1"
	"github.com/urfave/cli/v2"
)

func p1n(cCtx *cli.Context) error {
	// sanity check
	if cCtx.Args().Len() != 2 {
		return errors.New("please provide the power and output path arguments")
	}
	powerStr := cCtx.Args().Get(0)
	power, err := strconv.Atoi(powerStr)
	if err != nil {
		return err
	}
	if power > 26 {
		return errors.New("can't support powers larger than 26")
	}
	outputPath := cCtx.Args().Get(1)
	err = phase1.Initialize(byte(power), outputPath)
	return err
}

func p1c(cCtx *cli.Context) error {
	// sanity check
	if cCtx.Args().Len() != 2 {
		return errors.New("please provide the input and output path")
	}
	inputPath := cCtx.Args().Get(0)
	outputPath := cCtx.Args().Get(1)
	err := phase1.Contribute(inputPath, outputPath)
	return err
}

func p1v(cCtx *cli.Context) error {
	// sanity check
	if cCtx.Args().Len() != 1 {
		return errors.New("please provide the input path")
	}
	inputPath := cCtx.Args().Get(0)
	err := phase1.Verify(inputPath)
	return err
}