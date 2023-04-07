package phase2

import (
	"encoding/gob"
	"io"
)

type Header struct {
	Wires							int
	Witness          	int
	Public           	int
	PrivateCommitted 	int
	Constraints				int
	Domain           	int
	Contributions    	int
}

func (p *Header) Read(reader io.Reader) error {
	dec := gob.NewDecoder(reader)
	if err := dec.Decode(p); err != nil {
		return err
	}
	return nil
}

func (p *Header) write(writer io.Writer) error {
	enc := gob.NewEncoder(writer)
	if err := enc.Encode(*p); err != nil {
		return err
	}
	return nil
}
