package rawdb

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	elaCom "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/utils/http"

	"github.com/elastos/Elastos.ELA.SideChain/service"

	"github.com/elastos/Elastos.ELA.SideChain.EID/common"
	"github.com/elastos/Elastos.ELA.SideChain.EID/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.EID/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.EID/ethdb"
	"github.com/elastos/Elastos.ELA.SideChain.EID/log"
	"github.com/elastos/Elastos.ELA.SideChain.EID/params"
)

type EntryPrefix byte

const (
	IX_VerifiableCredentialRevoked       EntryPrefix = 0x86
	IX_DIDVerifiableCredentials          EntryPrefix = 0x87
	IX_ISDID                             EntryPrefix = 0x88
	IX_DeactivateCustomizedDID           EntryPrefix = 0x89
	IX_VerifiableCredentialExpiresHeight EntryPrefix = 0x90
	IX_VerifiableCredentialTXHash        EntryPrefix = 0x91
	IX_VerifiableCredentialPayload       EntryPrefix = 0x92
	IX_CUSTOMIZEDDIDPayload              EntryPrefix = 0x93
	IX_CUSTOMIZEDDIDTXHash               EntryPrefix = 0x94
	IX_DIDTXHash                         EntryPrefix = 0x95
	IX_DIDPayload                        EntryPrefix = 0x96
	IX_DIDExpiresHeight                  EntryPrefix = 0x97
	IX_DIDDeactivate                     EntryPrefix = 0x98
	IX_CUSTOMIZEDDIDExpiresHeight        EntryPrefix = 0x99
)

var (
	ERR_READ_TX               = errors.New("read transaction error")
	ERR_READ_RECEIPT          = errors.New("read receipt error")
	ERR_NOT_DIDRECEIPT        = errors.New("receipt is not contain did")
	ERR_NOT_DEACTIVATERECEIPT = errors.New("receipt is not contain deactivate tx")
	ERR_NOT_FOUND             = errors.New("not found")
	ERR_LEVELDB_NOT_FOUND     = errors.New("leveldb: not found")
)

func PersistRegisterDIDTx(db ethdb.KeyValueStore, log *types.DIDLog, blockHeight uint64,
	blockTimeStamp uint64) error {
	fmt.Println("PersistRegisterDIDTx begin")
	var err error
	var buffer *bytes.Reader
	operation := new(did.DIDPayload)
	buffer = bytes.NewReader(log.Data)
	err = operation.Deserialize(buffer, did.DIDVersion)
	if err != nil {
		return err
	}
	isDID := uint64(0)
	if did.IsDID(operation.DIDDoc.ID, operation.DIDDoc.PublicKey) {
		isDID = 1
	}
	idKey := []byte{}
	//customized id store lower
	if isDID != 1 {
		idKey = []byte(strings.ToLower(operation.DIDDoc.ID))
	} else {
		idKey = []byte(operation.DIDDoc.ID)
	}

	expiresHeight, err := TryGetExpiresHeight(operation.DIDDoc.Expires, blockHeight, blockTimeStamp)
	if err != nil {
		return err
	}

	if err := PersistRegisterDIDExpiresHeight(db, idKey, expiresHeight); err != nil {
		return err
	}

	thash, err := elaCom.Uint256FromBytes(log.TxHash.Bytes())
	if err != nil {
		return err
	}
	if err := persistRegisterDIDTxHash(db, idKey, *thash); err != nil {
		return err
	}

	// didPayload is persisted in receipt
	//if err := persistRegisterDIDPayload(db, *thash, operation); err != nil {
	//	return err
	//}

	if err := PersistIsDID(db, idKey, isDID); err != nil {
		return err
	}
	fmt.Println("PersistRegisterDIDTx end")

	return nil
}

func PersistIsDID(db ethdb.KeyValueStore, idKey []byte, isDID uint64) error {
	key := []byte{byte(IX_ISDID)}
	key = append(key, idKey...)

	buf := new(bytes.Buffer)
	if err := elaCom.WriteVarUint(buf, isDID); err != nil {
		return err
	}
	return db.Put(key, buf.Bytes())
}

func IsDID(db ethdb.KeyValueStore, did string) (bool, error) {
	idKey := new(bytes.Buffer)
	idKey.WriteString(did)

	key := []byte{byte(IX_ISDID)}
	key = append(key, idKey.Bytes()...)

	data, err := db.Get(key)
	if err != nil {
		return false, err
	}
	r := bytes.NewReader(data)
	// get the count of expires height
	isDID, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return false, err
	}
	if isDID == 1 {
		return true, nil
	}
	return false, nil
}

func TryGetExpiresHeight(Expires string, blockHeight uint64, blockTimeStamp uint64) (uint64, error) {
	expiresTime, err := time.Parse(time.RFC3339, Expires)
	if err != nil {
		return 0, errors.New("invalid Expires")
	}

	var timeSpanSec, expiresSec uint64
	expiresSec = uint64(expiresTime.Unix())
	timeSpanSec = expiresSec - blockTimeStamp

	if expiresSec < blockTimeStamp {
		timeSpanSec = 0
	}
	//needsBlocks := timeSpanSec / (2 * 60)
	needsBlocks := timeSpanSec / 5
	expiresHeight := blockHeight + needsBlocks
	return expiresHeight, nil
}

func GetDIDExpiresHeight(db ethdb.KeyValueStore, idKey []byte) (uint32, error) {
	key := []byte{byte(IX_DIDExpiresHeight)}
	key = append(key, idKey...)

	var expiresBlockHeight uint32
	data, err := db.Get(key)
	if err != nil {
		return 0, err
	}

	r := bytes.NewReader(data)
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return 0, err
	}
	if count == 0 {
		return 0, errors.New("not exist")
	}
	if expiresBlockHeight, err = elaCom.ReadUint32(r); err != nil {
		return 0, err
	}
	return expiresBlockHeight, nil
}

func GetCredentialExpiresHeight(db ethdb.KeyValueStore, idKey []byte) (uint32, error) {
	key := []byte{byte(IX_VerifiableCredentialExpiresHeight)}
	key = append(key, idKey...)

	var expiresBlockHeight uint32
	data, err := db.Get(key)
	if err != nil {
		return 0, err
	}

	r := bytes.NewReader(data)
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return 0, err
	}
	if count == 0 {
		return 0, errors.New("not exist")
	}
	if expiresBlockHeight, err = elaCom.ReadUint32(r); err != nil {
		return 0, err
	}
	return expiresBlockHeight, nil
}

func PersistRegisterDIDExpiresHeight(db ethdb.KeyValueStore, idKey []byte,
	expiresHeight uint64) error {
	key := []byte{byte(IX_DIDExpiresHeight)}
	key = append(key, idKey...)
	data, err := db.Get(key)
	if err != nil {
		if err.Error() != ERR_LEVELDB_NOT_FOUND.Error() && err.Error() != ERR_NOT_FOUND.Error() {
			return err
		}
		// when not exist, only put the current expires height into db.
		buf := new(bytes.Buffer)
		if err := elaCom.WriteVarUint(buf, 1); err != nil {
			return err
		}
		if err := elaCom.WriteUint64(buf, expiresHeight); err != nil {
			return err
		}

		return db.Put(key, buf.Bytes())
	}

	// when exist, should add current expires height to the end of the list.
	r := bytes.NewReader(data)
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	count++

	buf := new(bytes.Buffer)

	// write count
	if err := elaCom.WriteVarUint(buf, count); err != nil {
		return err
	}
	if err := elaCom.WriteUint64(buf, expiresHeight); err != nil {
		return err
	}
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}

	return db.Put(key, buf.Bytes())
}

// key                                                    value
// IX_VerifiableCredentialRevoked+ credentialID             controller
func persistVerifyCredentialRevoked(db ethdb.KeyValueStore, credentialID []byte, revokerID string) error {
	key := []byte{byte(IX_VerifiableCredentialRevoked)}
	key = append(key, credentialID...)

	data, err := db.Get(key)
	if err != nil {
		if err.Error() != ERR_LEVELDB_NOT_FOUND.Error() && err.Error() != ERR_NOT_FOUND.Error() {
			return err
		}
		// when not exist, only put the current payload hash into db.
		buf := new(bytes.Buffer)
		if err := elaCom.WriteVarUint(buf, 1); err != nil {
			return err
		}
		err = elaCom.WriteVarString(buf, revokerID)
		if err != nil {
			return errors.New(fmt.Sprintf("[persistVerifyCredentialRevoked], WriteVarString revokerID %s error ",
				revokerID))
		}
		return db.Put(key, buf.Bytes())
	}

	// when exist, should add current payload hash to the end of the list.
	r := bytes.NewReader(data)
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	count++

	buf := new(bytes.Buffer)

	// write count
	if err := elaCom.WriteVarUint(buf, count); err != nil {
		return err
	}

	err = elaCom.WriteVarString(buf, revokerID)
	if err != nil {
		return errors.New(fmt.Sprintf("[persistDIDVerifCredentials], WriteVarString2 revokerID %s error ",
			revokerID))
	}

	// write old credential ids
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}
	return db.Put(key, buf.Bytes())
}

func persistRegisterDIDTxHash(db ethdb.KeyValueStore, idKey []byte, txHash elaCom.Uint256) error {
	key := []byte{byte(IX_DIDTXHash)}
	key = append(key, idKey...)

	data, err := db.Get(key)
	if err != nil {
		if err.Error() != ERR_LEVELDB_NOT_FOUND.Error() && err.Error() != ERR_NOT_FOUND.Error() {
			return err
		}
		// when not exist, only put the current payload hash into db.
		buf := new(bytes.Buffer)
		if err := elaCom.WriteVarUint(buf, 1); err != nil {
			return err
		}

		if err := txHash.Serialize(buf); err != nil {
			return err
		}
		return db.Put(key, buf.Bytes())
	}

	// when exist, should add current payload hash to the end of the list.
	r := bytes.NewReader(data)
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	count++

	buf := new(bytes.Buffer)

	// write count
	if err := elaCom.WriteVarUint(buf, count); err != nil {
		return err
	}

	// write current payload hash
	if err := txHash.Serialize(buf); err != nil {
		return err
	}

	// write old hashes
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}

	return db.Put(key, buf.Bytes())
}

func GetLastDIDTxData(db ethdb.KeyValueStore, blockNumber *big.Int, idKey []byte, config *params.ChainConfig) (*did.DIDTransactionData, error) {
	key := []byte{byte(IX_DIDTXHash)}
	key = append(key, idKey...)

	data, err := db.Get(key)
	if err != nil {
		log.Error("GetLastDIDTxData", "getkey", string(key), "error", err.Error())
		return nil, err
	}

	r := bytes.NewReader(data)
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		log.Error("GetLastDIDTxData", "ReadVarUint", count, "error", err.Error())
		return nil, err
	}
	if count == 0 {
		return nil, errors.New("not exist")
	}
	var txHash elaCom.Uint256
	if err := txHash.Deserialize(r); err != nil {
		return nil, err
	}

	thash := common.BytesToHash(txHash.Bytes())
	recp, _, _, _ := ReadReceipt(db.(ethdb.Database), thash, config)
	if recp == nil {
		if recps := ReadReceipts(db.(ethdb.Database), thash, blockNumber.Uint64(), config); recps != nil {
			c := recps.Len()
			if c > 0 {
				recp = recps[c-1]
			}
		}
	}

	if recp == nil {
		log.Error("not found receipt tx="+thash.String(), "blockNumber", blockNumber.Uint64(), "count", count)
		return nil, ERR_READ_RECEIPT
	}
	if recp.DIDLog.DID == "" {
		return nil, ERR_NOT_DIDRECEIPT
	}
	tempOperation := new(did.DIDPayload)
	r = bytes.NewReader(recp.DIDLog.Data)
	err = tempOperation.Deserialize(r, did.DIDVersion)
	if err != nil {
		return nil, http.NewError(int(service.ResolverInternalError),
			"tempOperation Deserialize failed")
	}
	tempTxData := new(did.DIDTransactionData)
	tempTxData.TXID = txHash.String()
	tempTxData.Operation = *tempOperation
	tempTxData.Timestamp = tempOperation.DIDDoc.Expires

	return tempTxData, nil
}

func GetDeactivatedTxData(db ethdb.KeyValueStore, blockNumber *big.Int, idKey []byte, config *params.ChainConfig) (*did.DIDTransactionData, error) {
	key := []byte{byte(IX_DIDDeactivate)}
	key = append(key, idKey...)

	data, err := db.Get(key)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(data)
	var txHash elaCom.Uint256
	if err := txHash.Deserialize(r); err != nil {
		return nil, err
	}

	thash := common.BytesToHash(txHash.Bytes())
	recp, _, _, _ := ReadReceipt(db.(ethdb.Database), thash, config)
	if recp == nil {
		if recps := ReadReceipts(db.(ethdb.Database), thash, blockNumber.Uint64(), config); recps != nil {
			c := recps.Len()
			if c > 0 {
				recp = recps[c-1]
			}
		}
	}

	if recp == nil {
		return nil, ERR_READ_RECEIPT
	}
	if recp.DIDLog.DID == "" {
		return nil, ERR_NOT_DEACTIVATERECEIPT
	}

	tempOperation := new(did.DIDPayload)
	r = bytes.NewReader(recp.DIDLog.Data)
	err = tempOperation.Deserialize(r, did.DIDVersion)
	if err != nil {
		return nil, errors.New("[DIDPayload], tempOperation Deserialize failed")
	}
	tempTxData := new(did.DIDTransactionData)
	tempTxData.TXID = txHash.String()
	tempTxData.Operation = *tempOperation
	return tempTxData, nil
}

func IsDIDDeactivated(db ethdb.KeyValueStore, did string) bool {
	idKey := new(bytes.Buffer)
	idKey.WriteString(did)

	key := []byte{byte(IX_DIDDeactivate)}
	key = append(key, idKey.Bytes()...)

	_, err := db.Get(key)
	if err != nil {
		return false
	}
	return true
}

func GetAllDIDTxTxData(db ethdb.KeyValueStore, idKey []byte, config *params.ChainConfig) ([]did.DIDTransactionData, error) {
	key := []byte{byte(IX_DIDTXHash)}
	key = append(key, idKey...)

	data, err := db.Get(key)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(data)
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return nil, err
	}
	var transactionsData []did.DIDTransactionData
	for i := uint64(0); i < count; i++ {
		var txHash elaCom.Uint256
		if err := txHash.Deserialize(r); err != nil {
			return nil, err
		}
		thash := common.BytesToHash(txHash.Bytes())
		if txn, _, _, _ := ReadTransaction(db.(ethdb.Database), common.BytesToHash(txHash.Bytes())); txn == nil {
			return nil, ERR_READ_TX
		}

		recp, _, _, _ := ReadReceipt(db.(ethdb.Database), thash, config)
		if recp == nil {
			return nil, ERR_READ_RECEIPT
		}

		if recp.DIDLog.DID == "" {
			return nil, ERR_NOT_DIDRECEIPT
		}
		tempOperation := new(did.DIDPayload)
		r := bytes.NewReader(recp.DIDLog.Data)
		err = tempOperation.Deserialize(r, did.DIDVersion)
		if err != nil {
			return nil, http.NewError(int(service.InvalidTransaction),
				"payloaddid Deserialize failed")
		}
		tempTxData := new(did.DIDTransactionData)
		tempTxData.TXID = txHash.String()
		tempTxData.Operation = *tempOperation
		tempTxData.Timestamp = tempOperation.DIDDoc.Expires
		transactionsData = append(transactionsData, *tempTxData)
	}

	return transactionsData, nil
}

// get all controller who revoked this credential
// IX_VerifiableCredentialRevoked
func GetRevokeCredentialCtrls(db ethdb.KeyValueStore, credentIDKey []byte) ([]string, error) {
	key := []byte{byte(IX_VerifiableCredentialRevoked)}
	key = append(key, credentIDKey...)
	var ctrls []string

	data, err := db.Get(key)
	if err != nil {
		return ctrls, err
	}

	r := bytes.NewReader(data)
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return ctrls, err
	}

	for i := uint64(0); i < count; i++ {

		ctrl, err := elaCom.ReadVarString(r)
		if err != nil {
			return nil, err
		}
		ctrls = append(ctrls, ctrl)

	}
	return ctrls, nil
}

func GetLastCustomizedDIDTxData(db ethdb.KeyValueStore, idKey []byte) (*did.DIDTransactionData, error) {
	key := []byte{byte(IX_CUSTOMIZEDDIDTXHash)}
	key = append(key, idKey...)

	data, err := db.Get(key)
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(data)
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, errors.New("not exist")
	}
	var txHash elaCom.Uint256
	if err := txHash.Deserialize(r); err != nil {
		return nil, err
	}

	keyPayload := []byte{byte(IX_CUSTOMIZEDDIDPayload)}
	keyPayload = append(keyPayload, txHash.Bytes()...)

	dataPayload, err := db.Get(keyPayload)
	if err != nil {
		return nil, err
	}

	tempOperation := new(did.DIDPayload)
	r = bytes.NewReader(dataPayload)
	err = tempOperation.Deserialize(r, did.DIDVersion)
	if err != nil {
		return nil, http.NewError(int(service.ResolverInternalError),
			"DIDPayload Deserialize failed")
	}
	tempTxData := new(did.DIDTransactionData)
	tempTxData.TXID = txHash.String()
	tempTxData.Operation = *tempOperation
	tempTxData.Timestamp = tempOperation.GetDIDDoc().Expires

	return tempTxData, nil
}

func persistRegisterDIDPayload(db ethdb.KeyValueStore, txHash elaCom.Uint256, p *did.DIDPayload) error {
	key := []byte{byte(IX_DIDPayload)}
	key = append(key, txHash.Bytes()...)

	buf := new(bytes.Buffer)
	p.Serialize(buf, did.DIDVersion)
	return db.Put(key, buf.Bytes())
}

func IsURIHasPrefix(id string) bool {
	return strings.HasPrefix(id, did.DID_ELASTOS_PREFIX)
}

func isCustomizeDIDExist(db ethdb.KeyValueStore, ID string) (bool, error) {
	lowerID := strings.ToLower(ID)
	fmt.Println("lowerID", lowerID)
	isDID, err := IsDID(db, lowerID)
	if err != nil {
		return false, err
	}
	return !isDID, nil
}

func PersistDeactivateDIDTx(db ethdb.KeyValueStore, log *types.DIDLog, thash common.Hash) error {
	ok, err := IsDID(db, log.DID)
	fmt.Println("PersistDeactivateDIDTx", "DID", log.DID, "ok", ok, "err", err)
	if err != nil {
		if err.Error() == ERR_LEVELDB_NOT_FOUND.Error() || err.Error() == ERR_NOT_FOUND.Error() {
			//custDID
			_, err := isCustomizeDIDExist(db, log.DID)
			fmt.Println("PersistDeactivateDIDTx isCustomizeDIDExist err", err)
			if err != nil {
				return err
			}
			ok = false
		} else {
			return err
		}
	}
	id := log.DID
	if !ok {
		id = strings.ToLower(log.DID)
	}
	fmt.Println("PersistDeactivateDIDTx", "id", id)

	key := []byte{byte(IX_DIDDeactivate)}
	idKey := []byte(id)
	key = append(key, idKey...)

	buf := new(bytes.Buffer)
	txHash, err := elaCom.Uint256FromBytes(thash.Bytes())
	if err != nil {
		return err
	}
	if err := txHash.Serialize(buf); err != nil {
		return err
	}
	return db.Put(key, buf.Bytes())
}

func GetAllVerifiableCredentialTxData(db ethdb.KeyValueStore, blockNumber *big.Int, idKey []byte, config *params.ChainConfig) ([]did.VerifiableCredentialTxData, error) {
	key := []byte{byte(IX_VerifiableCredentialTXHash)}
	key = append(key, idKey...)

	data, err := db.Get(key)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(data)
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return nil, err
	}
	var transactionsData []did.VerifiableCredentialTxData
	for i := uint64(0); i < count; i++ {
		var txHash elaCom.Uint256
		if err := txHash.Deserialize(r); err != nil {
			return nil, err
		}
		//keyPayload := []byte{byte(IX_VerifiableCredentialPayload)}
		//keyPayload = append(keyPayload, txHash.Bytes()...)
		thash := common.BytesToHash(txHash.Bytes())
		recp, _, _, _ := ReadReceipt(db.(ethdb.Database), thash, config)
		if recp == nil {
			if recps := ReadReceipts(db.(ethdb.Database), thash, blockNumber.Uint64(), config); recps != nil {
				c := recps.Len()
				if c > 0 {
					recp = recps[c-1]
				}
			}
		}

		if recp == nil {
			return nil, ERR_READ_RECEIPT
		}
		if recp.DIDLog.DID == "" {
			return nil, ERR_NOT_DIDRECEIPT
		}
		vcPayload := new(did.DIDPayload)
		r := bytes.NewReader(recp.DIDLog.Data)
		err = vcPayload.Deserialize(r, did.VerifiableCredentialVersion)
		if err != nil {
			return nil, http.NewError(int(service.InvalidTransaction),
				"verifiable credential payload Deserialize failed")
		}
		tempTxData := new(did.VerifiableCredentialTxData)
		tempTxData.TXID = txHash.String()
		if vcPayload.CredentialDoc != nil {
			tempTxData.Timestamp = vcPayload.CredentialDoc.ExpirationDate
		}
		tempTxData.Operation = *vcPayload
		transactionsData = append(transactionsData, *tempTxData)
	}

	return transactionsData, nil
}

func GetLastVerifiableCredentialTxData(db ethdb.KeyValueStore, blockNumber *big.Int, idKey []byte, config *params.ChainConfig) (*did.DIDTransactionData, error) {
	key := []byte{byte(IX_VerifiableCredentialTXHash)}
	key = append(key, idKey...)

	data, err := db.Get(key)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(data)
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, errors.New("not exist")
	}
	var txHash elaCom.Uint256
	if err := txHash.Deserialize(r); err != nil {
		return nil, err
	}

	//keyPayload := []byte{byte(IX_VerifiableCredentialPayload)}
	//keyPayload = append(keyPayload, txHash.Bytes()...)

	thash := common.BytesToHash(txHash.Bytes())
	recp, _, _, _ := ReadReceipt(db.(ethdb.Database), thash, config)
	if recp == nil {
		if recps := ReadReceipts(db.(ethdb.Database), thash, blockNumber.Uint64(), config); recps != nil {
			c := recps.Len()
			if c > 0 {
				recp = recps[c-1]
			}
		}
	}

	if recp == nil {
		return nil, ERR_READ_RECEIPT
	}
	if recp.DIDLog.DID == "" {
		return nil, ERR_NOT_DIDRECEIPT
	}

	credentialPayload := new(did.DIDPayload)
	r = bytes.NewReader(recp.DIDLog.Data)
	err = credentialPayload.Deserialize(r, did.VerifiableCredentialVersion)
	if err != nil {
		return nil, http.NewError(int(service.ResolverInternalError),
			"tempOperation Deserialize failed")
	}
	tempTxData := new(did.DIDTransactionData)
	tempTxData.TXID = txHash.String()
	tempTxData.Operation = *credentialPayload
	if credentialPayload.CredentialDoc != nil {
		tempTxData.Timestamp = credentialPayload.CredentialDoc.ExpirationDate
	}
	return tempTxData, nil
}

func DeleteDIDLog(db ethdb.KeyValueStore, didLog *types.DIDLog) error {
	if didLog == nil {
		return errors.New("didLog is nil")
	}
	id := didLog.DID
	if id == "" {
		return errors.New("invalid regPayload.DIDDoc.ID")
	}
	switch didLog.Operation {
	case did.Create_DID_Operation, did.Update_DID_Operation, did.Transfer_DID_Operation:
		if err := rollbackRegisterDIDLog(db, []byte(id), didLog.TxHash); err != nil {
			return err
		}
	case did.Deactivate_DID_Operation:
		if err := rollbackDeactivateDIDTx(db, []byte(id)); err != nil {
			return err
		}
	case did.Declare_Verifiable_Credential_Operation:
		if err := rollbackVerifiableCredentialTx(db, []byte(id), didLog.TxHash); err != nil {
			return err
		}
	case did.Revoke_Verifiable_Credential_Operation:
		if err := rollbackRevokeVerifiableCredentialTx(db, []byte(id)); err != nil {
			return err
		}
	}
	return nil
}

// //roll back IX_VerifiableCredentialTXHash, IX_VerifiableCredentialRevoked
// //rollbackRevokeVerifiableCredentialTx
func rollbackRevokeVerifiableCredentialTx(db ethdb.KeyValueStore, credentialIDKey []byte) error {

	key := []byte{byte(IX_VerifiableCredentialRevoked)}
	key = append(key, credentialIDKey...)

	data, err := db.Get(key)
	if err != nil {
		return err
	}

	r := bytes.NewReader(data)
	// get the count of credential ids
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("not exist")
	}
	_, err = elaCom.ReadVarString(r)
	if err != nil {
		return err
	}

	//todo rollback IX_VerifiableCredentialTXHash
	if count == 1 {
		return db.Delete(key)
	}

	buf := new(bytes.Buffer)
	// write count
	if err := elaCom.WriteVarUint(buf, count-1); err != nil {
		return err
	}
	// write old credential ids
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}
	return db.Put(key, buf.Bytes())
}

// rollbackVerifiableCredentialTx
// todo roll back IX_VerifiableCredentialTXHash and i credentials
func rollbackVerifiableCredentialTx(db ethdb.KeyValueStore, credentialIDKey []byte, thash common.Hash) error {
	key := []byte{byte(IX_VerifiableCredentialTXHash)}
	key = append(key, credentialIDKey...)

	data, err := db.Get(key)
	if err != nil {
		return err
	}

	r := bytes.NewReader(data)
	// get the count of tx hashes
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("not exist")
	}
	// get the newest tx hash
	var txHash elaCom.Uint256
	if err := txHash.Deserialize(r); err != nil {
		return err
	}
	// if not rollback the newest tx hash return error
	hash, err := elaCom.Uint256FromBytes(thash.Bytes())
	if err != nil {
		return err
	}
	if !txHash.IsEqual(*hash) {
		log.Error("rollbackVerifiableCredentialTx", "last txHash", txHash.String(), "hash", hash.String())
		return errors.New("not rollback the last one")
	}

	//rollback operation (payload)
	//may be need del
	keyPayload := []byte{byte(IX_VerifiableCredentialPayload)}
	keyPayload = append(keyPayload, txHash.Bytes()...)
	db.Delete(keyPayload)

	//rollback expires height
	err = rollbackVerifiableCredentialExpiresHeight(db, credentialIDKey)
	if err != nil {
		return err
	}

	err = rollbackDIDVerifCredentials(db, credentialIDKey)
	if err != nil {
		return err
	}

	if count == 1 {
		return db.Delete(key)
	}

	buf := new(bytes.Buffer)
	// write count
	if err := elaCom.WriteVarUint(buf, count-1); err != nil {
		return err
	}
	// write old hashes
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}
	return db.Put(key, buf.Bytes())
}

func rollbackVerifiableCredentialExpiresHeight(db ethdb.KeyValueStore,
	credentialIDKey []byte) error {

	key := []byte{byte(IX_VerifiableCredentialExpiresHeight)}
	key = append(key, credentialIDKey...)

	data, err := db.Get(key)
	if err != nil {
		return err
	}

	r := bytes.NewReader(data)
	// get the count of expires height
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("not exist")
	}

	if _, err = elaCom.ReadUint64(r); err != nil {
		return err
	}

	if count == 1 {
		return db.Delete(key)
	}

	buf := new(bytes.Buffer)

	// write count
	if err := elaCom.WriteVarUint(buf, count-1); err != nil {
		return err
	}

	// write old expires height
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}

	return db.Put(key, buf.Bytes())
}

func rollbackRegisterDIDLog(db ethdb.KeyValueStore, idKey []byte, txhash common.Hash) error {
	log.Error("rollbackRegisterDIDLog", "id", string(idKey), "txhash", txhash.String())
	key := []byte{byte(IX_DIDTXHash)}
	key = append(key, idKey...)

	data, err := db.Get(key)
	if err != nil {
		return err
	}

	r := bytes.NewReader(data)
	// get the count of tx hashes
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("not exist")
	}

	// get the newest tx hash
	var txHash elaCom.Uint256
	if err := txHash.Deserialize(r); err != nil {
		return err
	}
	// if not rollback the newest tx hash return error
	hash, err := elaCom.Uint256FromBytes(txhash.Bytes())
	if err != nil {
		return err
	}
	if !txHash.IsEqual(*hash) {
		log.Error("rollbackRegisterDIDLog", "last txHash", txHash.String(), "hash", hash.String())
		return errors.New("not rollback the last one")
	}

	//keyPayload := []byte{byte(IX_DIDPayload)}
	//keyPayload = append(keyPayload, txHash.Bytes()...)
	//db.Delete(keyPayload)

	//rollback expires height
	err = rollbackRegisterDIDExpiresHeight(db, idKey)
	if err != nil {
		return err
	}

	if count == 1 {
		return db.Delete(key)
	}

	buf := new(bytes.Buffer)
	// write count
	if err := elaCom.WriteVarUint(buf, count-1); err != nil {
		return err
	}
	// write old hashes
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}
	return db.Put(key, buf.Bytes())
}

func rollbackDeactivateDIDTx(db ethdb.KeyValueStore, idKey []byte) error {
	key := []byte{byte(IX_DIDDeactivate)}
	key = append(key, idKey...)

	_, err := db.Get(key)
	if err != nil {
		return err
	}
	db.Delete(key)
	return nil
}

func rollbackIsDID(db ethdb.KeyValueStore,
	idKey []byte) error {
	key := []byte{byte(IX_ISDID)}
	key = append(key, idKey...)

	_, err := db.Get(key)
	if err != nil {
		return err
	}
	db.Delete(key)
	return nil
}

func rollbackRegisterDIDExpiresHeight(db ethdb.KeyValueStore, idKey []byte) error {
	key := []byte{byte(IX_DIDExpiresHeight)}
	key = append(key, idKey...)

	data, err := db.Get(key)
	if err != nil {
		return err
	}

	r := bytes.NewReader(data)
	// get the count of expires height
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("not exist")
	}

	if _, err = elaCom.ReadUint64(r); err != nil {
		return err
	}

	if count == 1 {
		return db.Delete(key)
	}

	buf := new(bytes.Buffer)

	// write count
	if err := elaCom.WriteVarUint(buf, count-1); err != nil {
		return err
	}

	// write old expires height
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}

	return db.Put(key, buf.Bytes())
}

func getCredentialOwner(credentialSubject interface{}) string {
	creSub := credentialSubject.(map[string]interface{})
	owner := ""
	for k, v := range creSub {
		if k == did.ID_STRING {
			owner = v.(string)
			break
		}
	}
	return owner
}

// persistVerifiableCredentialTx
func PersistVerifiableCredentialTx(db ethdb.KeyValueStore, log *types.DIDLog,
	blockHeight uint64, blockTimeStamp uint64, thash common.Hash) error {
	var err error
	var buffer *bytes.Reader
	payload := new(did.DIDPayload)
	buffer = bytes.NewReader(log.Data)
	err = payload.Deserialize(buffer, did.DIDVersion)
	if err != nil {
		return err
	}
	id := payload.CredentialDoc.ID
	contrl, uri := did.GetController(id)
	ok, err := isDID(db, contrl)
	if err != nil {
		return err
	}
	//customizedid
	if !ok {
		id = strings.ToLower(contrl) + uri
	}

	idKey := []byte(id)

	verifyCred := payload.CredentialDoc
	expiresHeight, err := TryGetExpiresHeight(verifyCred.ExpirationDate, blockHeight, blockTimeStamp)
	if err != nil {
		return err
	}

	if err := persistVerifiableCredentialExpiresHeight(db, idKey, expiresHeight); err != nil {
		return err
	}
	txhash, err := elaCom.Uint256FromBytes(thash.Bytes())
	if err != nil {
		return err
	}
	if err := persisterifiableCredentialTxHash(db, idKey, txhash); err != nil {
		return err
	}
	//didPayload is persisted in receipt
	//if err := persistVerifiableCredentialPayload(db, txhash, payload); err != nil {
	//	return err
	//}
	//only declare credentials will be stored
	//reocrd owner's credential id
	if payload.Header.Operation == did.Declare_Verifiable_Credential_Operation {
		owner := getCredentialOwner(payload.CredentialDoc.CredentialSubject)
		ok, err := isDID(db, owner)
		if err != nil {
			return err
		}
		//customizedid
		if !ok {
			owner = strings.ToLower(owner)
		}
		fmt.Println("PersistVerifiableCredentialTx", "owner", owner, "verifyCred.ID", verifyCred.ID)
		if err := persistDIDVerifCredentials(db, []byte(owner), verifyCred.ID); err != nil {
			return err
		}
	}

	return nil
}

// persistVerifiableCredentialTx
func PersistRevokeVerifiableCredentialTx(db ethdb.KeyValueStore, log *types.DIDLog,
	blockHeight uint64, blockTimeStamp uint64, thash common.Hash) error {
	var err error
	var buffer *bytes.Reader
	payload := new(did.DIDPayload)
	buffer = bytes.NewReader(log.Data)
	err = payload.Deserialize(buffer, did.DIDVersion)
	if err != nil {
		return err
	}
	// check is ID is customized or did
	credID := log.DID
	contrl, uri := did.GetController(credID)
	isOwnerDID, err := isDID(db, contrl)
	if err != nil {
		return err
	}
	//customizedid
	if !isOwnerDID {
		credID = strings.ToLower(contrl) + uri
	}

	revokerID, uri := did.GetController(payload.Proof.VerificationMethod)

	credIDKey := []byte(credID)

	txhash, err := elaCom.Uint256FromBytes(thash.Bytes())
	if err != nil {
		return err
	}
	if err := persisterifiableCredentialTxHash(db, credIDKey, txhash); err != nil {
		return err
	}
	fmt.Println("PersistRevokeVerifiableCredentialTx", "credID", credID, "revokerID", revokerID)

	if err = persistVerifyCredentialRevoked(db, credIDKey, revokerID); err != nil {
		return err
	}

	return nil
}

func persistVerifiableCredentialExpiresHeight(db ethdb.KeyValueStore,
	idKey []byte, expiresHeight uint64) error {
	key := []byte{byte(IX_VerifiableCredentialExpiresHeight)}
	key = append(key, idKey...)

	data, err := db.Get(key)
	if err != nil {
		if err.Error() != ERR_LEVELDB_NOT_FOUND.Error() && err.Error() != ERR_NOT_FOUND.Error() {
			return err
		}
		// when not exist, only put the current expires height into db.
		buf := new(bytes.Buffer)
		if err := elaCom.WriteVarUint(buf, 1); err != nil {
			return err
		}
		if err := elaCom.WriteUint64(buf, expiresHeight); err != nil {
			return err
		}

		return db.Put(key, buf.Bytes())
	}

	// when exist, should add current expires height to the end of the list.
	r := bytes.NewReader(data)
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	count++

	buf := new(bytes.Buffer)

	// write count
	if err := elaCom.WriteVarUint(buf, count); err != nil {
		return err
	}
	if err := elaCom.WriteUint64(buf, expiresHeight); err != nil {
		return err
	}
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}

	return db.Put(key, buf.Bytes())
}

func persisterifiableCredentialTxHash(db ethdb.KeyValueStore, idKey []byte, txHash *elaCom.Uint256) error {
	key := []byte{byte(IX_VerifiableCredentialTXHash)}
	key = append(key, idKey...)

	data, err := db.Get(key)
	if err != nil {
		if err.Error() != ERR_LEVELDB_NOT_FOUND.Error() && err.Error() != ERR_NOT_FOUND.Error() {
			return err
		}
		// when not exist, only put the current payload hash into db.
		buf := new(bytes.Buffer)
		if err := elaCom.WriteVarUint(buf, 1); err != nil {
			return err
		}

		if err := txHash.Serialize(buf); err != nil {
			return err
		}

		return db.Put(key, buf.Bytes())
	}

	// when exist, should add current payload hash to the end of the list.
	r := bytes.NewReader(data)
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	count++

	buf := new(bytes.Buffer)

	// write count
	if err := elaCom.WriteVarUint(buf, count); err != nil {
		return err
	}

	// write current payload hash
	if err := txHash.Serialize(buf); err != nil {
		return err
	}

	// write old hashes
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}

	return db.Put(key, buf.Bytes())
}

func persistVerifiableCredentialPayload(db ethdb.KeyValueStore,
	txHash *elaCom.Uint256, p *did.DIDPayload) error {
	key := []byte{byte(IX_VerifiableCredentialPayload)}
	key = append(key, txHash.Bytes()...)

	buf := new(bytes.Buffer)
	p.Serialize(buf, did.VerifiableCredentialVersion)
	return db.Put(key, buf.Bytes())
}

func persistDIDVerifCredentials(db ethdb.KeyValueStore, idKey []byte, credentilaID string) error {
	key := []byte{byte(IX_DIDVerifiableCredentials)}
	key = append(key, idKey...)

	data, err := db.Get(key)
	if err != nil {
		if err.Error() != ERR_LEVELDB_NOT_FOUND.Error() && err.Error() != ERR_NOT_FOUND.Error() {
			return err
		}
		// when not exist, only put the current payload hash into db.
		buf := new(bytes.Buffer)
		if err := elaCom.WriteVarUint(buf, 1); err != nil {
			return err
		}
		err = elaCom.WriteVarString(buf, credentilaID)
		if err != nil {
			return errors.New(fmt.Sprintf("[persistDIDVerifCredentials], WriteVarString credentilaID %s error ",
				credentilaID))
		}
		return db.Put(key, buf.Bytes())
	}

	// when exist, should add current payload hash to the end of the list.
	r := bytes.NewReader(data)
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	count++

	buf := new(bytes.Buffer)

	// write count
	if err := elaCom.WriteVarUint(buf, count); err != nil {
		return err
	}

	err = elaCom.WriteVarString(buf, credentilaID)
	if err != nil {
		return errors.New(fmt.Sprintf("[persistDIDVerifCredentials], WriteVarString2 credentilaID %s error ",
			credentilaID))
	}

	// write old credential ids
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}
	return db.Put(key, buf.Bytes())
}

func rollbackDIDVerifCredentials(db ethdb.KeyValueStore, idKey []byte) error {

	key := []byte{byte(IX_DIDVerifiableCredentials)}
	key = append(key, idKey...)

	data, err := db.Get(key)
	if err != nil {
		return err
	}

	r := bytes.NewReader(data)
	// get the count of credential ids
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("not exist")
	}
	_, err = elaCom.ReadVarString(r)
	if err != nil {
		return err
	}

	if count == 1 {
		return db.Delete(key)
	}

	buf := new(bytes.Buffer)
	// write count
	if err := elaCom.WriteVarUint(buf, count-1); err != nil {
		return err
	}
	// write old credential ids
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}
	return db.Put(key, buf.Bytes())
}

// IX_DIDVerifiableCredentials
func GetAllDIDVerifCredentials(db ethdb.KeyValueStore, idKey []byte, skip, limit int64) (*did.ListDIDVerifCreentials, error) {
	key := []byte{byte(IX_DIDVerifiableCredentials)}
	key = append(key, idKey...)

	var credentials did.ListDIDVerifCreentials
	credentials.DID = string(idKey)
	data, err := db.Get(key)
	if err != nil {
		return &credentials, err
	}

	r := bytes.NewReader(data)
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return &credentials, err
	}
	//-1 means all
	if limit < 0 {
		limit = int64(count)
	}
	end := int64(0)
	if skip < int64(count) {
		end = skip
		if skip+limit <= int64(count) {
			end = skip + limit
		} else {
			end = int64(count)
		}
	}
	for i := int64(0); i < end; i++ {
		if i < skip {
			_, err := elaCom.ReadVarString(r)
			if err != nil {
				return nil, err
			}
			continue
		}
		credID, err := elaCom.ReadVarString(r)
		if err != nil {
			return nil, err
		}
		credentials.Credentials = append(credentials.Credentials, credID)
	}
	return &credentials, nil
}

func isDID(db ethdb.KeyValueStore, ID string) (bool, error) {
	ret, err := IsDID(db, ID)
	if err != nil {
		if err.Error() == ERR_LEVELDB_NOT_FOUND.Error() || err.Error() == ERR_NOT_FOUND.Error() {
			//custDID
			_, err := isCustomizeDIDExist(db, ID)
			if err != nil {
				return false, err
			}
			ret = false
		} else {
			return false, err
		}
	}
	return ret, nil
}
