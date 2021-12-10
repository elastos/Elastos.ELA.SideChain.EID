package ethapi

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/elastos/Elastos.ELA.SideChain/service"

	elacom "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/utils/http"

	"github.com/elastos/Elastos.ELA.SideChain.EID/common"
	"github.com/elastos/Elastos.ELA.SideChain.EID/core/rawdb"
	"github.com/elastos/Elastos.ELA.SideChain.EID/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.EID/ethdb"
	"github.com/elastos/Elastos.ELA.SideChain.EID/internal/didapi"
)

// payload of DID transaction
type RpcCredentialPayloadDIDInfo struct {
	ID         string                         `json:"id"`
	Status     int                            `json:"status"`
	RpcTXDatas []RpcCredentialTransactionData `json:"transaction,omitempty"`
}

type RpcCredentialTransactionData struct {
	TXID      string              `json:"txid"`
	Timestamp string              `json:"timestamp"`
	Operation CredentialOperation `json:"operation"`
}

type CredentialOperation struct {
	Header  did.Header  `json:"header"`
	Payload string      `json:"payload"`
	Proof   interface{} `json:"proof"`
}

//xxl add new register API
// NewPublicDebugAPI creates a new API definition for the public debug methods
// of the Ethereum service.
func NewPublicDIDAPI(b Backend, nonceLock *AddrLocker) *PublicTransactionPoolAPI {
	return &PublicTransactionPoolAPI{b, nonceLock}
}

func (rpcTxData *RpcCredentialTransactionData) FromCredentialTranasactionData(txData did.
	VerifiableCredentialTxData) bool {
	hash, err := elacom.Uint256FromHexString(txData.TXID)
	if err != nil {
		return false
	}

	rpcTxData.TXID = service.ToReversedString(*hash)
	rpcTxData.Timestamp = txData.Timestamp
	rpcTxData.Operation.Header = txData.Operation.Header
	rpcTxData.Operation.Payload = txData.Operation.Payload
	rpcTxData.Operation.Proof = txData.Operation.Proof
	return true
}

func (s *PublicTransactionPoolAPI) isDID(idParam string) (bool, error){

	idWithPrefix := idParam
	if !rawdb.IsURIHasPrefix(idWithPrefix) {
		//add prefix
		idWithPrefix = did.DID_ELASTOS_PREFIX + idParam
	}
	buf := new(bytes.Buffer)
	buf.WriteString(idWithPrefix)
	_, err := rawdb.GetLastDIDTxData(s.b.ChainDb().(ethdb.KeyValueStore), buf.Bytes(), s.b.ChainConfig())
	if err != nil {

		idWithPrefix= strings.ToLower(idWithPrefix)
		buf.Reset()
		//buf = new(bytes.Buffer)
		buf.WriteString(idWithPrefix)
		//try customized id
		_, err = rawdb.GetLastDIDTxData(s.b.ChainDb().(ethdb.KeyValueStore), buf.Bytes(), s.b.ChainConfig())
		if err != nil {
			//if we can not find customized then it means non exist
			return false , err
		}
		return  false , nil
	}
	return true, nil
}

func (s *PublicTransactionPoolAPI) ResolveCredential(ctx context.Context, param map[string]interface{}) (interface{}, error) {
	idParam, ok := param["id"].(string)
	if !ok {
		return nil, http.NewError(int(service.InvalidParams), "id is null")
	}

	credentialIDWithPrefix := idParam
	if !rawdb.IsURIHasPrefix(credentialIDWithPrefix) {
		//add prefix
		credentialIDWithPrefix = did.DID_ELASTOS_PREFIX + idParam
	}
	controller ,uri := did.GetController(credentialIDWithPrefix)

	isDID, err := s.isDID(controller)
	if err != nil {
		return nil, http.NewError(int(service.InvalidParams), "idParam controller not found")
	}
	//customizedid
	if !isDID {
		credentialIDWithPrefix = strings.ToLower(controller)+uri
	}

	credentialID := credentialIDWithPrefix
	buf := new(bytes.Buffer)
	buf.WriteString(credentialID)
	// credentialID can be customized
	txsData, err := rawdb.GetAllVerifiableCredentialTxData(s.b.ChainDb().(ethdb.KeyValueStore), buf.Bytes(), s.b.ChainConfig())
	if err != nil {
		return  nil , http.NewError(int(service.InvalidParams), "get credentialID failed")
	}

	//check issuer
	issuer, ok := param["issuer"].(string)
	isDID = false
	var issuerID string
	if issuer != "" {
		issuerID = issuer
		//isDID, err =s.isDID(issuerID)
		//if err != nil {
		//	return nil, http.NewError(int(service.InvalidParams), "issuerID not exist")
		//}
	}

	var rpcPayloadDid RpcCredentialPayloadDIDInfo
	for _, txData := range txsData {
		if txData.Operation.CredentialDoc == nil&& txData.Operation.Header.Operation == did.Revoke_Verifiable_Credential_Operation{
			rpcPayloadDid.ID = txData.Operation.Payload
		}else{
			rpcPayloadDid.ID = txData.Operation.CredentialDoc.ID
		}
		err, timestamp := s.getTxTime(ctx, txData.TXID)
		if err != nil {
			continue
		}
		tempTXData := new(RpcCredentialTransactionData)
		ok := tempTXData.FromCredentialTranasactionData(txData)
		if !ok {
			continue
		}

		var onlyRevokeTX bool
		//only revoke
		if len(txsData) == 1 && txData.Operation.Header.Operation == did.Revoke_Verifiable_Credential_Operation {
			onlyRevokeTX = true
		}

		if onlyRevokeTX{
			// revoker is owner ignore issureid
			revoker, _ := did.GetController(txData.Operation.Proof.VerificationMethod)
			credeOwner, _ := did.GetController(rpcPayloadDid.ID)
			if revoker !=credeOwner {
				if issuerID != ""{
					isDID, err =s.isDID(issuerID)
					if err != nil {
						return nil, http.NewError(int(service.InvalidParams), "issuerID not exist")
					}
					if !isDID {
						issuerID = strings.ToLower(issuerID)
						credeOwner = strings.ToLower(credeOwner)
					}
					if issuerID != revoker {
						continue
					}
				}
			}
		}

		tempTXData.Timestamp = time.Unix(int64(timestamp), 0).UTC().Format(time.RFC3339)
		rpcPayloadDid.RpcTXDatas = append(rpcPayloadDid.RpcTXDatas, *tempTXData)
	}

	if len(txsData) == 0 {
		rpcPayloadDid.Status = didapi.CredentialNonExist
		rpcPayloadDid.ID = idParam
	} else if len(txsData) == 1 {
		if txsData[0].Operation.Header.Operation ==did.Declare_Verifiable_Credential_Operation {
			rpcPayloadDid.Status = didapi.CredentialValid
		}else{
			rpcPayloadDid.Status = didapi.CredentialRevoked
		}

	} else if len(txsData) == 2 {
		rpcPayloadDid.Status = didapi.CredentialRevoked
	}

	return rpcPayloadDid, nil
}

func (s *PublicTransactionPoolAPI) ListCredentials(ctx context.Context, param map[string]interface{}) (interface{}, error) {
	idParam, ok := param["did"].(string)
	if !ok {
		return nil, http.NewError(int(service.InvalidParams), "did is null")
	}

	idWithPrefix := idParam
	if !rawdb.IsURIHasPrefix(idWithPrefix) {
		//add prefix
		idWithPrefix = did.DID_ELASTOS_PREFIX + idParam
	}
	buf := new(bytes.Buffer)
	buf.WriteString(idWithPrefix)
	_, err := rawdb.GetLastDIDTxData(s.b.ChainDb().(ethdb.KeyValueStore), buf.Bytes(), s.b.ChainConfig())
	if err != nil {

		idWithPrefix= strings.ToLower(idWithPrefix)
		buf.Reset()
		//buf = new(bytes.Buffer)
		buf.WriteString(idWithPrefix)
		//try customized id
		_, err = rawdb.GetLastDIDTxData(s.b.ChainDb().(ethdb.KeyValueStore), buf.Bytes(), s.b.ChainConfig())
		if err != nil {
			//if we can not find customized then it means non exist
			return nil, http.NewError(int(service.InvalidParams), "did is not exist")
		}
	}


	skip, ok := param["skip"].(float64)
	limit, ok := param["limit"].(float64)
	if int64(skip) < 0 {
		return nil, http.NewError(int(service.InvalidParams), "skip is negative")
	}

	if limit == 0{
		limit = 100
	}

	//credentialID := idParam
	//buf := new(bytes.Buffer)
	//buf.WriteString(credentialID)
	txsData, _ := rawdb.GetAllDIDVerifCredentials(s.b.ChainDb().(ethdb.KeyValueStore), buf.Bytes(), int64(skip),
		int64(limit))
	return txsData, nil
}


func (s *PublicTransactionPoolAPI) getDeactiveTx(ctx context.Context, idKey []byte) (*didapi.RpcTranasactionData, error) {
	//get deactive tx date
	deactiveTxData, err := rawdb.GetDeactivatedTxData(s.b.ChainDb().(ethdb.KeyValueStore), idKey,
		s.b.ChainConfig())
	if err != nil {
		return nil, http.NewError(int(service.InternalError),
			"get did deactivate transaction failed")
	}
	//change from DIDTransactionData to RpcTranasactionData
	rpcTXData := new(didapi.RpcTranasactionData)
	succe := rpcTXData.FromTranasactionData(*deactiveTxData)
	if succe == false {
		return nil, http.NewError(int(service.InternalError),
			"get did deactivate transaction failed")
	}
	//fill tx Timestamp
	err, timestamp := s.getTxTime(ctx, rpcTXData.TXID)
	if err != nil {
		return nil, http.NewError(int(service.InternalError),
			"get did deactivate transaction failed")
	}
	rpcTXData.Timestamp = time.Unix(int64(timestamp), 0).UTC().Format(time.RFC3339)
	return rpcTXData, nil
}

//xxl modify to PublicTransactionPoolAPI
func (s *PublicTransactionPoolAPI) ResolveDID(ctx context.Context, param map[string]interface{}) (interface{}, error) {
	var didDocState didapi.DidDocState = didapi.NonExist
	idParam, ok := param["did"].(string)
	if !ok {
		return nil, http.NewError(int(service.InvalidParams), "did is null")
	}

	isGetAll, ok := param["all"].(bool)
	if !ok {
		isGetAll = false
	}

	var rpcPayloadDid didapi.RpcPayloadDIDInfo


	idWithPrefix := idParam
	if !rawdb.IsURIHasPrefix(idWithPrefix) {
		//add prefix
		idWithPrefix = did.DID_ELASTOS_PREFIX + idParam
	}
	buf := new(bytes.Buffer)
	buf.WriteString(idWithPrefix)
	txData, err := rawdb.GetLastDIDTxData(s.b.ChainDb().(ethdb.KeyValueStore), buf.Bytes(), s.b.ChainConfig())
	if err != nil {

		idWithPrefix= strings.ToLower(idWithPrefix)
		buf.Reset()
		//buf = new(bytes.Buffer)
		buf.WriteString(idWithPrefix)
		//try customized id
		txData, err = rawdb.GetLastDIDTxData(s.b.ChainDb().(ethdb.KeyValueStore), buf.Bytes(), s.b.ChainConfig())
		if err != nil {
			//if we can not find customized then it means non exist
			rpcPayloadDid.DID = idParam
			rpcPayloadDid.Status = didapi.NonExist
			return rpcPayloadDid, nil
		}
	}

	var txsData []did.DIDTransactionData
	if isGetAll {
		txsData, err = rawdb.GetAllDIDTxTxData(s.b.ChainDb().(ethdb.KeyValueStore), buf.Bytes(), s.b.ChainConfig())
		if err != nil {
			return nil, http.NewError(int(service.InternalError),
				"get did transaction failed")
		}
	} else {
		if txData != nil {
			txsData = append(txsData, *txData)
		}
	}

	for index, txData := range txsData {
		rpcPayloadDid.DID = txData.Operation.DIDDoc.ID
		err, timestamp := s.getTxTime(ctx, txData.TXID)
		if err != nil {
			continue
		}
		tempTXData := new(didapi.RpcTranasactionData)
		succe := tempTXData.FromTranasactionData(txData)
		if succe == false {
			continue
		}

		tempTXData.Timestamp = time.Unix(int64(timestamp), 0).UTC().Format(time.RFC3339)
		if index == 0 {
			if rawdb.IsDIDDeactivated(s.b.ChainDb().(ethdb.KeyValueStore), idWithPrefix) {
				didDocState = didapi.Deactivated
				//fill in
				deactiveTXData, err := s.getDeactiveTx(ctx, buf.Bytes())
				if err != nil {
					return nil, err
				}
				rpcPayloadDid.RpcTXDatas = append(rpcPayloadDid.RpcTXDatas, *deactiveTXData)
			} else {
				didDocState = didapi.Valid
			}
			rpcPayloadDid.Status = int(didDocState)
		}
		rpcPayloadDid.RpcTXDatas = append(rpcPayloadDid.RpcTXDatas, *tempTXData)
	}
	return rpcPayloadDid, nil
}

func (s *PublicTransactionPoolAPI) getTxTime(ctx context.Context, txid string) (error, uint64) {
	hash := common.HexToHash(txid)

	tx, err := s.GetTransactionByHash(ctx, hash)
	if err != nil || tx == nil {
		return errors.New("unkown tx"), 0
	}
	block, err := s.b.BlockByHash(ctx, *tx.BlockHash)
	if err != nil {
		return errors.New("unkown block header"), 0

	}
	return nil, block.Time()
}
