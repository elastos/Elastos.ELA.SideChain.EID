package crosschain

import (
	"github.com/elastos/Elastos.ELA.SideChain.EID/common"
	"github.com/elastos/Elastos.ELA.SideChain.EID/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.EID/spv"
)

func IsRechargeTx(tx *types.Transaction) bool {
	if tx == nil || tx.To() == nil {
		return false
	}
	var empty common.Address
	if *tx.To() == empty {
		if len(tx.Data()) == 32 {
			return true
		}
		rawTxid, _, _ , _ := spv.IsSmallCrossTxByData(tx.Data())
		if rawTxid != "" {
			return true
		}
	}
	return false
}
