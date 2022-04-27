package did

import (
	"bytes"

	"golang.org/x/text/unicode/norm"
)

type NFCBuffer struct {
	*bytes.Buffer
}

func (buf *NFCBuffer) Write(b []byte) (n int, err error) {
	return buf.Buffer.Write(ToNFCBytes(b))
}

func (buf *NFCBuffer) WriteString(s string) (n int, err error) {
	return buf.Buffer.WriteString(ToNFCString(s))
}

func (buf *NFCBuffer) WriteKey(key string) error {
	sig, err := JSONMarshal(key)
	if err != nil {
		return err
	}
	if _, err := buf.Write(sig); err != nil {
		return err
	}
	if _, err := buf.WriteString(":"); err != nil {
		return err
	}

	return nil
}

func ToNFCString(s string) string {
	return norm.NFC.String(s)
}

func ToNFCBytes(b []byte) []byte {
	return norm.NFC.Bytes(b)
}

func NewNFCBuffer() *NFCBuffer {
	return &NFCBuffer{new(bytes.Buffer)}
}
