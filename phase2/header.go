package phase2

import (
	"encoding/gob"
	"io"
)

type Header struct {
	Wires            int
	Witness          int
	Public           int
	PrivateCommitted int
	Constraints      int
	Domain           int
	Contributions    int
}

func (h *Header) Read(reader io.Reader) error {
	dec := gob.NewDecoder(reader)
	if err := dec.Decode(h); err != nil {
		return err
	}
	return nil
}

func (h *Header) write(writer io.Writer) error {
	enc := gob.NewEncoder(writer)
	if err := enc.Encode(*h); err != nil {
		return err
	}
	return nil
}

func (h *Header) Equal(h2 *Header) bool {
	if h.Wires == h2.Wires &&
		h.Witness == h2.Witness &&
		h.Public == h2.Public &&
		h.PrivateCommitted == h2.PrivateCommitted &&
		h.Constraints == h2.Constraints &&
		h.Domain == h2.Domain {
		return true
	}
	return false
}
