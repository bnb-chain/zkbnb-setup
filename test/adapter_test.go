package test

import (
	"testing"

	"github.com/bnb-chain/zkbnb-setup/phase1"
)

func TestTransform(t *testing.T) {
	if err := phase1.Transform("new_challenge", "0.ph1", 10, 8); err != nil {
		t.Error(err)
	}
	if err:= phase1.Contribute("0.ph1", "1.ph1"); err!= nil {
		t.Error(err)
	}
	if err:= phase1.Contribute("1.ph1", "2.ph1"); err!= nil {
		t.Error(err)
	}
	if err:= phase1.Verify("2.ph1", "0.ph1"); err!=nil {
		t.Error(err)
	}
}
