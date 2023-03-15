package main

import (
	"errors"
	"strconv"

	"github.com/bnbchain/zkbnb-setup/setup"
	"github.com/urfave/cli/v2"
)

func p1n(cCtx *cli.Context) error {
	// sanity check
	if cCtx.Args().Len() != 1 {
		return errors.New("please provide the power argument")
	}
	powerStr := cCtx.Args().Get(0)
	power, err := strconv.Atoi(powerStr)
	if err != nil {
		return err
	}
	if power > 26 {
		return errors.New("can't support powers larger than 26")
	}
	err = setup.InitializePhaseOne(byte(power))
	return err
}
