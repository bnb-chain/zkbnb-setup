package phase2

import (
	"crypto/sha256"
	"io"
)

func hashR1CSFile(reader io.Reader) ([]byte, error) {
	h := sha256.New()
	if _, err := io.Copy(h, reader); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
