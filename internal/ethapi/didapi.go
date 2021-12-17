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
	"github.com/elastos/Elastos.ELA.SideChain.EID/core/vm"
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


//IDS shoule be issuer or owner
func (s *PublicTransactionPoolAPI) isRevokerValid(revoker  string, IDS []string)(bool,error){
	for _, id := range IDS {
		var idTxData *did.DIDTransactionData
		isDID, err := s.isDID(id)
		if err != nil {
			return  false, err
		}
		lowerID := id
		if !isDID{
			lowerID= strings.ToLower(id)
		}
		if idTxData, err = rawdb.GetLastDIDTxData(s.b.ChainDb().(ethdb.KeyValueStore), []byte(lowerID), s.b.ChainConfig()); err != nil {
			return   false ,err
		}

		if isDID {
			if revoker == id {
				return true, nil
			}
		}else{
			//check if customizedid owner have ctrl
			if revoker == id {
				return true, nil
			}
			if vm.HaveCtrl(idTxData.Operation.DIDDoc.Controller, revoker) {
				return true, nil
			}

		}
	}
	return false ,nil
}

func (s *PublicTransactionPoolAPI) ResolveCredential(ctx context.Context, param map[string]interface{}) (interface{}, error) {
	idParam, ok := param["id"].(string)
	if !ok {
		return nil, http.NewError(int(service.InvalidParams), "id is null")
	}
	var rpcPayloadDid RpcCredentialPayloadDIDInfo

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
		rpcPayloadDid.Status = didapi.CredentialNonExist
		rpcPayloadDid.ID = idParam
		return  rpcPayloadDid , nil
	}

	//check issuer
	issuer, ok := param["issuer"].(string)
	isDID = false
	var issuerID string
	if issuer != "" {
		issuerID = issuer
		if !rawdb.IsURIHasPrefix(issuerID) {
			//add prefix
			issuerID = did.DID_ELASTOS_PREFIX + issuer
		}
	}

	issuerRevokeTXData := new(RpcCredentialTransactionData)//if haveIssuerRevokeTx is true issuerRevokeTXData is the tx
	haveIssuerRevokeTx := false //if issuer param is one of the revoker set true
	haveValidRevoke := false//if revoked by issuer or owner  set true32Byte
	realIssuer :=""

	//find if we have declare tx of credential and stored it into realIssuer
	for _, txData := range txsData {
		if  txData.Operation.Header.Operation == did.Declare_Verifiable_Credential_Operation  {
			realIssuer = txData.Operation.CredentialDoc.Issuer
		}
	}

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

		// decalre always been added
		if  txData.Operation.Header.Operation == did.Declare_Verifiable_Credential_Operation  {
			tempTXData.Timestamp = time.Unix(int64(timestamp), 0).UTC().Format(time.RFC3339)
			rpcPayloadDid.RpcTXDatas = append(rpcPayloadDid.RpcTXDatas, *tempTXData)
		}else{
			//for revoke tx
			revoker, _ := did.GetController(txData.Operation.Proof.VerificationMethod)
			//if it is credential owner or issuer
			credeOwner, _ := did.GetController(rpcPayloadDid.ID)
			//do we have valid revoker
			ids := []string{credeOwner }
			if realIssuer != "" {
				ids = append(ids, realIssuer)
			}
			if !haveValidRevoke {
				//check if revoker is belong to  credowner or issuer
				haveValidRevoke , err = s.isRevokerValid(revoker, ids)
				if err != nil  {
					return nil, http.NewError(int(service.InvalidParams), "isRevokerValid credentialid owner/issuer")
				}
				//if we haveValidRevoke add it into RpcTXDatas
				if haveValidRevoke {
					tempTXData.Timestamp = time.Unix(int64(timestamp), 0).UTC().Format(time.RFC3339)
					rpcPayloadDid.RpcTXDatas = append(rpcPayloadDid.RpcTXDatas, *tempTXData)
				}
			}
			if issuerID != "" {
				//if we do not have validate revoke and issuerid parameter is not empty
				//try if we have one revoke tx by issuerID
				if !haveValidRevoke  && (!haveIssuerRevokeTx){
					ids := []string{ issuerID}
					haveIssuerRevokeTx , err = s.isRevokerValid(revoker, ids)
					if err != nil {
						if err.Error() != vm.ErrLeveldbNotFound.Error() && err.Error() != vm.ErrNotFound.Error()  {
							return nil, http.NewError(int(service.InvalidParams), "isRevokerValid issuer parameter")
						}
					}
					// if we have  Issuer Revoke Tx then store it into issuerRevokeTXData
					if haveIssuerRevokeTx {
						tempTXData.Timestamp = time.Unix(int64(timestamp), 0).UTC().Format(time.RFC3339)
						issuerRevokeTXData = tempTXData
					}
				}
			}else{
				if !haveValidRevoke{
					tempTXData.Timestamp = time.Unix(int64(timestamp), 0).UTC().Format(time.RFC3339)
					rpcPayloadDid.RpcTXDatas = append(rpcPayloadDid.RpcTXDatas, *tempTXData)
				}
			}
		}
	}
	// if we did not have valid revoke and do have issuer revoke tx  add it to  RpcTXDatas
	if !haveValidRevoke && haveIssuerRevokeTx{
		rpcPayloadDid.RpcTXDatas = append(rpcPayloadDid.RpcTXDatas, *issuerRevokeTXData)
	}
	//not declare and not revke situation 1
	if len(txsData) == 0 {
		rpcPayloadDid.Status = didapi.CredentialNonExist
		rpcPayloadDid.ID = idParam
	} else if len(txsData) == 1 {
		if txsData[0].Operation.Header.Operation ==did.Declare_Verifiable_Credential_Operation {
			rpcPayloadDid.Status = didapi.CredentialValid
		}else{
			rpcPayloadDid.Status = didapi.CredentialRevoked
		}

	} else if len(txsData) >= 2 {
		if haveValidRevoke {
			rpcPayloadDid.Status = didapi.CredentialRevoked
		}else{
			//declared
			if realIssuer != "" {
				rpcPayloadDid.Status = didapi.CredentialValid
			}else{
				rpcPayloadDid.Status = didapi.CredentialRevoked
			}
		}

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
