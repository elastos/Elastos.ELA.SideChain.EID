package vm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNFCDoc(t *testing.T) {
	var changeDocPayload2 []byte
	changeDocPayload2, _ = LoadJsonData("testdata/nfc1.json")
	err := checkDIDTransactionAfterMigrateHeight(changeDocPayload2, nil)
	assert.NoError(t, err)
}
