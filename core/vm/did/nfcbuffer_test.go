package did

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/text/unicode/norm"
)

func TestNewNFCBuffer(t *testing.T) {
	input := []string{
		"ä4a",
		"a\u03084a",
		"a\u0308a",
		"…",
	}

	for _, str := range input {
		buf := NewNFCBuffer()
		buf.WriteString(str)

		buf2 := new(bytes.Buffer)
		buf2.WriteString(norm.NFKD.String(str))

		assert.NotEqual(t, buf.Bytes(), buf2.Bytes())
	}
}

func TestToNFCString(t *testing.T) {

	input := []string{
		"ä4a",
		"a\u03084a",
		"a\u0308a",
	}

	for _, str := range input {
		assert.NotEqual(t, str, norm.NFC.String(str))
	}
}
