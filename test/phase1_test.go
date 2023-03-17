package test

import (
	"testing"

	"github.com/bnbchain/zkbnb-setup/setup"
)

func TestInitialize(t *testing.T) {
	setup.InitializePhaseOne(1, "0.ph1")
	setup.ContributePhaseOne("0.ph1", "1.ph1")
	if err :=setup.VerifyPhaseOne("1.ph1"); err!=nil{
		t.Error(err)
	}
}
