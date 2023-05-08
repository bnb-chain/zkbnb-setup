package test

import (
	"testing"

	"github.com/bnb-chain/zkbnb-setup/phase1"
)

func TestTransform(t *testing.T) {
	if err := phase1.Transform("challenge", "transformed", 12, 2); err != nil {
		t.Error(err)
	}
	phase1.Initialize(2, "compare")
}
