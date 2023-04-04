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

func (p *Header) ReadFrom(reader io.Reader) (int64, error) {
	// Witness
	buff := make([]byte, 4)
	var bytesRead int64 = 0

	n, err := reader.Read(buff)
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, err
	}
	p.Witness = binary.BigEndian.Uint32(buff)
	

	// Public
	n, err = reader.Read(buff)
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, err
	}
	p.Public = binary.BigEndian.Uint32(buff)

	// Constraints
	n, err = reader.Read(buff)
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, err
	}
	p.Constraints = binary.BigEndian.Uint32(buff)

	// Domain
	n, err = reader.Read(buff)
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, err
	}
	p.Domain = binary.BigEndian.Uint32(buff)

	// Contributions
	buff = buff[:2]
	n, err = reader.Read(buff)
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, err
	}
	p.Contributions = binary.BigEndian.Uint16(buff)

	return bytesRead, nil
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
