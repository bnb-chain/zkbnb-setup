package test

import (
	"testing"

	"github.com/bnbchain/zkbnb-setup/phase1"
)

func TestInitialize(t *testing.T) {
	phase1.Initialize(4, "0.ph1")
}

func TestContribute(t *testing.T) {
	phase1.Initialize(4, "0.ph1")
	if err := phase1.Contribute("0.ph1", "1.ph1"); err != nil {
		t.Error(err)
	}
}

func TestVerify(t *testing.T) {
	phase1.Initialize(8, "0.ph1")
	if err := phase1.Contribute("0.ph1", "1.ph1"); err != nil {
		t.Error(err)
	}
	if err := phase1.Contribute("1.ph1", "2.ph1"); err != nil {
		t.Error(err)
	}
	if err := phase1.Contribute("2.ph1", "3.ph1"); err != nil {
		t.Error(err)
	}
	if err := phase1.Contribute("3.ph1", "4.ph1"); err != nil {
		t.Error(err)
	}
	if err := phase1.Verify("4.ph1"); err != nil {
		t.Error(err)
	}
}
