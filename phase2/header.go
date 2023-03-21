package phase2

import (
	"encoding/binary"
	"io"
)

type Header struct {
	Witness       uint32
	Public        uint32
	Constraints   uint32
	Domain        uint32
	Contributions uint16
}

func (p *Header) ReadFrom(reader io.Reader) error {
	// Witness
	buff := make([]byte, 4)
	if _, err := reader.Read(buff); err != nil {
		return err
	}
	p.Witness = binary.BigEndian.Uint32(buff)

	// Public
	if _, err := reader.Read(buff); err != nil {
		return err
	}
	p.Public = binary.BigEndian.Uint32(buff)

	// Constraints
	if _, err := reader.Read(buff); err != nil {
		return err
	}
	p.Constraints = binary.BigEndian.Uint32(buff)

	// Domain
	if _, err := reader.Read(buff); err != nil {
		return err
	}
	p.Domain = binary.BigEndian.Uint32(buff)

	// Contributions
	buff = buff[:2]
	if _, err := reader.Read(buff); err != nil {
		return err
	}
	p.Contributions = binary.BigEndian.Uint16(buff)

	return nil
}

func (p *Header) writeTo(writer io.Writer) error {
	// Witness
	buff := make([]byte, 4)
	binary.BigEndian.PutUint32(buff, p.Witness)
	if _, err := writer.Write(buff); err != nil {
		return err
	}

	// Public
	binary.BigEndian.PutUint32(buff, p.Public)
	if _, err := writer.Write(buff); err != nil {
		return err
	}

	// Constraints
	binary.BigEndian.PutUint32(buff, p.Constraints)
	if _, err := writer.Write(buff); err != nil {
		return err
	}

	// Domain
	binary.BigEndian.PutUint32(buff, p.Domain)
	if _, err := writer.Write(buff); err != nil {
		return err
	}

	// Contributions
	buff = buff[:2]
	binary.BigEndian.PutUint16(buff, p.Contributions)
	if _, err := writer.Write(buff); err != nil {
		return err
	}

	return nil
}
