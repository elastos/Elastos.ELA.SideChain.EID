package vm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHtmlEscape(t *testing.T) {
	var changeDocPayload1 []byte
	changeDocPayload1, _ = LoadJsonData("testdata/htmlescape1.json")
	err := checkDIDTransactionAfterMigrateHeight(changeDocPayload1, nil)
	assert.NoError(t, err)

	var changeDocPayload2 []byte
	changeDocPayload2, _ = LoadJsonData("testdata/htmlescape2.json")
	err = checkDIDTransactionAfterMigrateHeight(changeDocPayload2, nil)
	assert.NoError(t, err)
}

