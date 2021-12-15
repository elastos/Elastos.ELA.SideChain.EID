package vm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"

	"github.com/elastos/Elastos.ELA.SideChain.EID/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.EID/core/vm/did/base64url"
	"github.com/elastos/Elastos.ELA.SideChain.EID/log"
	"github.com/elastos/Elastos.ELA.SideChain.EID/spv"

	"github.com/elastos/Elastos.ELA.SideChain/vm/interfaces"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/contract"
)

// Common errors.
var (
	ErrLeveldbNotFound = errors.New("leveldb: not found")
	ErrNotFound        = errors.New("not found")
)

// blockStatus is a bit field representing the validation state of the block.
type publicKeyType byte

const (
	//defualt public key
	DefaultPublicKey publicKeyType = iota

	//Authtication public key
	AuthPublicKey

	//Authorization key
	AuthorPublicKey
)

var didParam did.DIDParams

const PrefixCRDID contract.PrefixType = 0x67

//,config   *node.Config
func InitDIDParams(params did.DIDParams) {
	didParam = params
}
//Controller
func sortControllerSlice(controller interface{})  {
	if controllers, ok :=controller.([]interface{}); ok{
		sort.Sort(did.ControllerSlice(controllers))
		fmt.Println("controller",controller)
	}

}
//sort doc Authentication or Authorization
func sortAuthSlice(authSlice []interface{}) error {
	var strAuth []string
	var objsAuth = make(map[string]interface{})

	for _, auth := range authSlice {
		switch auth.(type) {
		case string:
			keyString := auth.(string)
			strAuth = append(strAuth, keyString)
		case map[string]interface{}:
			data, err := json.Marshal(auth)
			if err != nil {
				return err
			}
			didPublicKeyInfo := new(did.DIDPublicKeyInfo)
			err = json.Unmarshal(data, didPublicKeyInfo)
			if err != nil {
				return err
			}
			strAuth = append(strAuth, didPublicKeyInfo.ID)
			objsAuth[didPublicKeyInfo.ID] = auth
		default:
			return errors.New("[ID checkVerificationMethodV1] invalid  auth.(type)")
		}
	}
	sort.Strings(strAuth)
	for index, ID := range strAuth {
		_, ok := objsAuth[ID]
		if !ok {
			authSlice[index] = ID
		} else {
			authSlice[index] = objsAuth[ID]
		}
	}
	return nil
}

//sort doc slice by id
func sortDocSlice(verifyDoc *did.DIDDoc) error {
	log.Error("sortDocSlice verifyDoc.Controller", "Controller",verifyDoc.Controller)
	sortControllerSlice(verifyDoc.Controller)
	log.Error("sortDocSlice verifyDoc.Controller", "Controller",verifyDoc.Controller)

	sort.Sort(did.PublicKeysSlice(verifyDoc.PublicKey))
	sort.Sort(did.VerifiableCredentialSlice(verifyDoc.VerifiableCredential))
	for _, v := range verifyDoc.VerifiableCredential {
		sort.Strings(v.Type)
	}
	sort.Sort(did.ServiceSlice(verifyDoc.Service))
	if err := sortAuthSlice(verifyDoc.Authentication); err != nil {
		return err
	}
	if err := sortAuthSlice(verifyDoc.Authorization); err != nil {
		return err
	}
	return nil
}

//Is customizdid deactive or expired
func isCustomizedidInvalid(evm *EVM, idString string)error{
	idString= strings.ToLower(idString)
	deactived := isIDDeactive(evm,idString)
	if deactived {
		return errors.New("isCustomizedidInvalid customizedid deactived")
	}
	result , err := isControllerExpired(evm,idString)
	if result || err != nil {
		return  errors.New("isCustomizedidInvalid customized expired check fail")
	}
	return  nil

}

func checkRegisterDID(evm *EVM, p *did.DIDPayload, gas uint64) error {
	log.Debug("checkRegisterDID begin","evm.BlockNumber", evm.BlockNumber)

	idString := did.GetDIDFromUri(p.DIDDoc.ID)
	// check idstring
	if !IsLetterOrNumber(idString) {
		return errors.New("invalid  DID: only letter and number is allowed")
	}
	//todo add config height
	if evm.Context.BlockNumber.Cmp(evm.chainConfig.CustomizeDIDHeight) > 0  {
		if err := checkExpires(p.DIDDoc.Expires, evm.Time); err != nil {
			return  err
		}
	}

	if isIDDeactive(evm,idString) {
		return errors.New("DID is already deactivated")
	}
	//check txn fee use RequiredGas
	//fee := evm.GasPrice.Uint64() * gas
	configHeight := evm.chainConfig.OldDIDMigrateHeight
	configAddr := evm.chainConfig.OldDIDMigrateAddr
	senderAddr := evm.Context.Origin.String()

	if configHeight == nil || evm.Context.BlockNumber.Cmp(configHeight) > 0 || senderAddr != configAddr {
		// abnormal payload check
		if err := checkPayloadSyntax(p, evm, true); err != nil {
			log.Error("checkPayloadSyntax error", "error", err, "ID", p.DIDDoc.ID)
			return err
		}
		//if err := checkRegisterDIDTxFee(p, fee); err != nil {
		//	return err
		//}
	}

	if err := checkDIDOperation(evm, &p.Header, p.DIDDoc.ID); err != nil {
		return err
	}
	//payload proof should be default key
	if err := checkVerificationMethodV1(p.Proof.VerificationMethod,
		p.DIDDoc); err != nil {
		return err
	}
	// todo checkVerificationMethodVuse2  pubkeyCount++

	//payload VerificationMethod key should be  authen key
	publicKeyBase58, _ :=getDIDAutheneKey(p.Proof.VerificationMethod,p.DIDDoc.Authentication,p.DIDDoc.PublicKey)
	if publicKeyBase58 == "" {
		return errors.New("Not find proper publicKeyBase58")
	}
	//get code
	//var publicKeyByte []byte
	publicKeyByte := base58.Decode(publicKeyBase58)

	//var code []byte
	code, err := did.GetCodeByPubKey(publicKeyByte)
	if err != nil {
		return err
	}
	signature, _ := base64url.DecodeString(p.Proof.Signature)

	var success bool
	//outter header payload proof verify signature
	success, err = did.VerifyByVM(p, code, signature)
	if err != nil {
		return err
	}
	if !success {
		return errors.New("checkDIDTransaction [VM]  Check Sig FALSE")
	}
	doc := p.DIDDoc
	// if err = checkVerifiableCredentials(evm, doc.ID, doc.VerifiableCredential,
	// 	doc.Authentication, doc.PublicKey, nil, true); err != nil {
	// 	if err.Error() == "[VM] Check Sig FALSE" && evm.Context.BlockNumber.Cmp(configHeight) < 0{
	// 		log.Warn("checkRegisterDID end "," Check Sig FALSE ID", p.DIDDoc.ID)
	// 		return nil
	// 	}
	// 	return err
	// }

	if configHeight == nil || evm.Context.BlockNumber.Cmp(configHeight) > 0 || senderAddr != configAddr {
		DIDProofArray, err := getDocProof(p.DIDDoc.Proof)
		if len(DIDProofArray) <= 0 {
			return errors.New("checkDIDTransaction doc proof is empty str")
		}
		if err != nil {
			return err
		}
		var verifyDoc *did.DIDDoc
		verifyDoc = p.DIDDoc
		//evm.chainConfig.DocArraySortHeight didParam.DocArraySortHeight
		log.Info("checkRegisterDID", "evm.chainConfig.DocArraySortHeight", evm.chainConfig.DocArraySortHeight)
		if evm.Context.BlockNumber.Cmp(evm.chainConfig.DocArraySortHeight) > 0 {
			if err = sortDocSlice(verifyDoc); err != nil {
				return err
			}
		}
		//inner doc verify sign
		if err = checkDIDInnerProof(evm, p.DIDDoc.ID, DIDProofArray, doc.DIDPayloadData, len(DIDProofArray), verifyDoc); err != nil {
			return err
		}
	}
	return nil
}

func checkRegisterDIDTxFee(operation *did.DIDPayload, txFee uint64) error {
	//2. calculate the  fee that one cutomized did txls should paid
	//payload := operation.DIDDoc
	//buf := new(bytes.Buffer)
	//operation.Serialize(buf, did.DIDVersion)
	//
	//needFee := getIDTxFee(payload.ID, payload.Expires, operation.Header.Operation, nil, buf.Len())
	//log.Debug("#### checkRegisterDIDTxFee ", "needFee sela", needFee)
	//
	//toETHfee := needFee * float64(did.FeeRate)
	//if float64(txFee) < toETHfee {
	//	msg := fmt.Sprintf("invalid txFee, need %f, set %f", toETHfee, float64(txFee))
	//	return errors.New(msg)
	//}

	//check fee and should paid fee
	return nil
}

func checkCustomizedDIDTxFee(payload *did.DIDPayload, txFee uint64) error {
	//2. calculate the  fee that one cutomized did tx should paid
	//doc := payload.DIDDoc
	//buf := new(bytes.Buffer)
	//payload.Serialize(buf, did.DIDVersion)
	//needFee := getIDTxFee(doc.ID, doc.Expires, payload.Header.Operation, doc.Controller, buf.Len())
	//
	//toETHfee := needFee * float64(did.FeeRate)
	//
	//if float64(txFee) < toETHfee {
	//	msg := fmt.Sprintf("invalid txFee, need %f, set %f", toETHfee, float64(txFee))
	//	return errors.New(msg)
	//}

	//check fee and should paid fee
	return nil
}

//check operateion create---->db must not have
//                 update----->db must have
func checkDIDOperation(evm *EVM, header *did.Header,
	idUri string) error {
	buf := new(bytes.Buffer)
	buf.WriteString(idUri)

	if evm.StateDB.IsIDDeactivated(idUri) {
		return errors.New("DID is deactivated")
	}

	lastTXData, err := evm.StateDB.GetLastDIDTxData(buf.Bytes(), evm.chainConfig)

	dbExist := true
	if err != nil {
		if err.Error() == ErrLeveldbNotFound.Error() || err.Error() == ErrNotFound.Error() {
			dbExist = false
		} else {
			return err
		}
	}
	if dbExist {
		if header.Operation == did.Create_DID_Operation {
			return errors.New("DID WRONG OPERATION ALREADY EXIST")
		} else if header.Operation == did.Update_DID_Operation {
			//check PreviousTxid
			hash, err := common.Uint256FromHexString(header.PreviousTxid)
			if err != nil {
				return err
			}
			preTXID := hash.String()
			if preTXID[:2] == "0x" {
				preTXID = preTXID[:2]
			}
			if lastTXData.TXID[:2] == "0x" {
				lastTXData.TXID = lastTXData.TXID[2:]
			}
			configHeight := evm.chainConfig.OldDIDMigrateHeight
			if evm.Context.BlockNumber.Cmp(configHeight) > 0 {
				if lastTXData.TXID != preTXID {
					return errors.New("PreviousTxid IS NOT CORRECT")
				}
			}
		}
	} else {
		if header.Operation == did.Update_DID_Operation {
			return errors.New("DID WRONG OPERATION NOT EXIST")
		}
	}
	return nil
}

//Proof VerificationMethod must be in DIDDIDDoc Authentication or
//is did publickKey
func checkVerificationMethodV1(VerificationMethod string,
	DIDDoc *did.DIDDoc) error {
	masterPubKeyVerifyOk := false
	for i := 0; i < len(DIDDoc.PublicKey); i++ {
		if verificationMethodEqual(VerificationMethod, DIDDoc.PublicKey[i].ID) {
			pubKeyByte := base58.Decode(DIDDoc.PublicKey[i].PublicKeyBase58)
			//get did address
			didAddress, err := did.GetDIDAddress(pubKeyByte)
			if err != nil {
				return err
			}
			//didAddress must equal address in DID
			if didAddress == did.GetDIDFromUri(DIDDoc.ID) {
				masterPubKeyVerifyOk = true
				break
			}
		}
	}

	for _, auth := range DIDDoc.Authentication {
		switch auth.(type) {
		case string:
			keyString := auth.(string)
			if verificationMethodEqual(VerificationMethod, keyString) {
				return nil
			}
		case map[string]interface{}:
			data, err := json.Marshal(auth)
			if err != nil {
				return err
			}
			didPublicKeyInfo := new(did.DIDPublicKeyInfo)
			err = json.Unmarshal(data, didPublicKeyInfo)
			if err != nil {
				return err
			}
			if verificationMethodEqual(VerificationMethod, didPublicKeyInfo.ID) {
				return nil
			}
		default:
			return errors.New("[ID checkVerificationMethodV1] invalid  auth.(type)")
		}
	}
	if masterPubKeyVerifyOk {
		return nil
	}
	return errors.New("[ID checkVerificationMethodV1] wrong public key by VerificationMethod ")
}

func getDIDAutheneKey(verificationMethod string, authentication []interface{}, publicKey []did.DIDPublicKeyInfo) (string, error) {
	for _, auth := range authentication {
		switch auth.(type) {
		case string:
			keyString := auth.(string)
			if verificationMethodEqual(verificationMethod, keyString) {
				for _, pkInfo := range publicKey {
					if verificationMethodEqual(verificationMethod, pkInfo.ID) {
						return pkInfo.PublicKeyBase58, nil
					}
				}
			}
		case map[string]interface{}:
			data, err := json.Marshal(auth)
			if err != nil {
				return "", err
			}
			didPublicKeyInfo := new(did.DIDPublicKeyInfo)
			err = json.Unmarshal(data, didPublicKeyInfo)
			if err != nil {
				return "", err
			}
			if verificationMethodEqual(verificationMethod, didPublicKeyInfo.ID) {
				return didPublicKeyInfo.PublicKeyBase58, nil
			}
		default:
			return "", errors.New("[Operation checkVerificationMethodV0] invalid  auth.(type)")
		}
	}
	return "", nil
}

func verificationMethodEqual(verificationMethod string, vcid string) bool {
	contr1, uriFregment1 := did.GetController(verificationMethod)
	contr2, uriFregment2 := did.GetController(vcid)
	if contr1 == "" || contr2 == "" {
		return uriFregment1 == uriFregment2
	}
	return contr1 == contr2 && uriFregment1 == uriFregment2
}

//get did/cutsomizedid Authentication public key
//for did  includes default key + authentication key
//for customizedID includes self authen + controller authen+ controller default key
func getAuthenPublicKey(evm *EVM, verificationMethod string, isDID bool,
	publicKey []did.DIDPublicKeyInfo, authentication []interface{}, controller interface{}) (string, error) {
	if isDID {
		return getDIDAutheneKey(verificationMethod, authentication, publicKey)
	} else {
		return	getCustDIDAuthenKey(evm, verificationMethod, publicKey, authentication, controller)
	}
}

//authorization []interface{},
func getCustDIDDefKey(evm *EVM, verificationMethod string,  controller interface{}) (string, error) {
	contr, _ := did.GetController(verificationMethod)
	//2, check is proofUriSegment public key come from controller
	if controllerArray, bControllerArray := controller.([]interface{}); bControllerArray == true {
		//2.1 is controller exist
		for _, controller := range controllerArray {
			if controller == contr {
				doc, err := GetIDLastDoc(evm, contr)
				if err != nil {
					return "", err
				}
				return getDIDDefaultKey(contr, verificationMethod, doc.Authentication, doc.PublicKey)
			}
		}
	} else if controller, bController := controller.(string); bController == true {
		if controller == contr {
			doc, err := GetIDLastDoc(evm, contr)
			if err != nil {
				return "", err
			}
			return getDIDDefaultKey(contr, verificationMethod, doc.Authentication, doc.PublicKey)

		}
	}
	return "", nil
}

func getCustDIDAuthenKey(evm *EVM, verificationMethod string, publicKey []did.DIDPublicKeyInfo,
	authentication []interface{}, controller interface{}) (string, error) {
	contr, _ := did.GetController(verificationMethod)

	for _, auth := range authentication {
		switch auth.(type) {
		case string:
			keyString := auth.(string)
			if verificationMethodEqual(verificationMethod, keyString) {
				for _, pkInfo := range publicKey {
					if verificationMethodEqual(verificationMethod, pkInfo.ID) {
						return pkInfo.PublicKeyBase58, nil
					}
				}
			}
		case map[string]interface{}:
			data, err := json.Marshal(auth)
			if err != nil {
				return "", err
			}
			didPublicKeyInfo := new(did.DIDPublicKeyInfo)
			err = json.Unmarshal(data, didPublicKeyInfo)
			if err != nil {
				return "", err
			}
			if verificationMethodEqual(verificationMethod, didPublicKeyInfo.ID) {
				return didPublicKeyInfo.PublicKeyBase58, nil
			}
		}
	}
	//contr, _ := id.GetController(verificationMethod)
	//2, check is proofUriSegment public key come from controller
	if controllerArray, bControllerArray := controller.([]interface{}); bControllerArray == true {
		//2.1 is controller exist
		for _, controller := range controllerArray {
			if controller == contr {
				doc, err := GetIDLastDoc(evm, contr)
				if err != nil {
					return "", err
				}
				return  getDIDAutheneKey(verificationMethod, doc.Authentication, doc.PublicKey)

			}
		}
	} else if controller, bController := controller.(string); bController == true {
		if controller == contr {
			doc, err := GetIDLastDoc(evm, contr)
			if err != nil {
				return "", err
			}
			return getDIDAutheneKey(verificationMethod, doc.Authentication, doc.PublicKey)
		}
	}
	return "", nil
}

//authorization []interface{},
func getCustomizedIDPublicKey(evm *EVM, verificationMethod string, publicKey []did.DIDPublicKeyInfo,
	authentication []interface{}, controller interface{}, keyType publicKeyType) (string, error) {
	contr, _ := did.GetController(verificationMethod)

	if keyType == AuthPublicKey {
		for _, auth := range authentication {
			switch auth.(type) {
			case string:
				keyString := auth.(string)
				if verificationMethodEqual(verificationMethod, keyString) {
					for _, pkInfo := range publicKey {
						if verificationMethodEqual(verificationMethod, pkInfo.ID) {
							return pkInfo.PublicKeyBase58, nil
						}
					}
				}
			case map[string]interface{}:
				data, err := json.Marshal(auth)
				if err != nil {
					return "", err
				}
				didPublicKeyInfo := new(did.DIDPublicKeyInfo)
				err = json.Unmarshal(data, didPublicKeyInfo)
				if err != nil {
					return "", err
				}
				if verificationMethodEqual(verificationMethod, didPublicKeyInfo.ID) {
					return didPublicKeyInfo.PublicKeyBase58, nil
				}
			}
		}
	}
	//contr, _ := id.GetController(verificationMethod)
	//2, check is proofUriSegment public key come from controller
	if controllerArray, bControllerArray := controller.([]interface{}); bControllerArray == true {
		//2.1 is controller exist
		for _, controller := range controllerArray {
			if controller == contr {
				doc, err := GetIDLastDoc(evm, contr)
				if err != nil {
					return "", err
				}
				//todo getDIDDefaultKey
				return getDIDPublicKeyByType(contr, verificationMethod, doc.Authentication, doc.PublicKey,
					doc.Authorization, keyType)
			}
		}
	} else if controller, bController := controller.(string); bController == true {
		if controller == contr {
			doc, err := GetIDLastDoc(evm, contr)
			if err != nil {
				return "", err
			}
			//todo getDIDDefaultKey
			return getDIDPublicKeyByType(contr, verificationMethod, doc.Authentication, doc.PublicKey,
				doc.Authorization, keyType)
		}
	}
	return "", nil
}

func getDIDPublicKeyByType(didWithPrefix, verificationMethod string, authentication []interface{},
	publicKey []did.DIDPublicKeyInfo, authorization []interface{}, keyType publicKeyType) (string, error) {
	var pubKeyBase58Str string
	var err error
	switch keyType {
	case DefaultPublicKey:
		pubKeyBase58Str, err = getDIDDefaultKey(didWithPrefix, verificationMethod, authentication, publicKey)
	case AuthorPublicKey:
		pubKeyBase58Str, err = getDIDDeactivateKey(didWithPrefix, verificationMethod, authentication, publicKey, authorization)
	case AuthPublicKey:
		pubKeyBase58Str, err = getDIDAutheneKey(verificationMethod, authentication, publicKey)
	}
	if pubKeyBase58Str == "" {
		return "", err
	}
	return pubKeyBase58Str, nil
}

func getDIDDeactivateKey(ID, verificationMethod string, authentication []interface{}, publicKey []did.DIDPublicKeyInfo,
	authorization []interface{}) (string, error) {
	publickeyBase58, _ := getDIDDefaultKey(ID, verificationMethod, authentication, publicKey)
	if publickeyBase58 == "" {
		for _, auth := range authorization {
			switch auth.(type) {
			case string:
				keyString := auth.(string)
				if verificationMethodEqual(verificationMethod, keyString) {
					for i := 0; i < len(publicKey); i++ {
						if verificationMethodEqual(verificationMethod, publicKey[i].ID) {
							return publicKey[i].PublicKeyBase58, nil
						}
					}
					return "", nil
				}
			case map[string]interface{}:
				data, err := json.Marshal(auth)
				if err != nil {
					return "", err
				}
				didPublicKeyInfo := new(did.DIDPublicKeyInfo)
				err = json.Unmarshal(data, didPublicKeyInfo)
				if err != nil {
					return "", err
				}
				if verificationMethodEqual(verificationMethod, didPublicKeyInfo.ID) {
					return didPublicKeyInfo.PublicKeyBase58, nil
				}
			default:
				return "", nil
			}
		}
	} else {
		return publickeyBase58, nil
	}

	return "", nil
}

func getDIDDefaultKey(dID, verificationMethod string, authentication []interface{}, publicKey []did.DIDPublicKeyInfo) (string, error) {
	didAddress := did.GetDIDFromUri(dID)
	for _, auth := range authentication {
		switch auth.(type) {
		case string:
			keyString := auth.(string)
			if verificationMethodEqual(verificationMethod, keyString) {
				for _, pkInfo := range publicKey {
					if verificationMethodEqual(verificationMethod, pkInfo.ID) {
						if did.IsPublickDIDMatched(pkInfo.PublicKeyBase58, didAddress) {
							return pkInfo.PublicKeyBase58, nil
						}
					}
				}
			}
		case map[string]interface{}:
			data, err := json.Marshal(auth)
			if err != nil {
				return "", err
			}
			didPublicKeyInfo := new(did.DIDPublicKeyInfo)
			err = json.Unmarshal(data, didPublicKeyInfo)
			if err != nil {
				return "", err
			}
			if verificationMethodEqual(verificationMethod, didPublicKeyInfo.ID) {
				if did.IsPublickDIDMatched(didPublicKeyInfo.PublicKeyBase58, didAddress) {
					return didPublicKeyInfo.PublicKeyBase58, nil
				}
			}
		default:
			return "", errors.New("[Operation checkVerificationMethodV0] invalid  auth.(type)")
		}
	}
	return "", nil
}

func GetIDLastDoc(evm *EVM, id string) (*did.DIDDoc, error) {
	TranasactionData, err := GetLastDIDTxData(evm, id)
	if err != nil {
		return nil, err
	}
	if TranasactionData == nil {
		return nil, errors.New("prefixDid DID not exist in level db")
	}
	return TranasactionData.Operation.DIDDoc, nil
}

func GetLastDIDTxData(evm *EVM, issuerDID string) (*did.DIDTransactionData, error) {
	buf := new(bytes.Buffer)
	buf.WriteString(issuerDID)
	lastTXData, err := evm.StateDB.GetLastDIDTxData(buf.Bytes(), evm.chainConfig)

	if err != nil {
		if err.Error() == ErrLeveldbNotFound.Error() || err.Error() == ErrNotFound.Error() {
			return nil, nil
		} else {
			return nil, err
		}
	}
	return lastTXData, nil
}

func Unmarshal(src, target interface{}) error {
	data, err := json.Marshal(src)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(data, target); err != nil {
		return err
	}
	return nil
}

func checkCredential(evm *EVM, credential *did.VerifiableCredential) error {

	var issuerPublicKey, issuerCode, signature []byte
	//var err error
	var issuerDoc *did.DIDDoc
	credOwner := GetCredentialOwner(credential.CredentialSubject)
	proof := credential.Proof
	realIssuer := getCredentialIssuer(credOwner, credential)
	isDID , err := isDID(evm, realIssuer)
	if err!= nil {
		return err
	}

	if isDID {
		issuerDoc, err = GetIDLastDoc(evm, realIssuer)
		if err != nil {
			log.Error("checkIDVerifiableCredential the GetIDLastDoc ", "err", err)
			return err
		}
		//realIssuer is self and Issuer is not ""
		ctrlInvalid, err := isControllerInvalid(evm,realIssuer)
		if  err!= nil{
			return err
		}
		if ctrlInvalid {
			return errors.New("realIssuer is ctrlInvalid")
		}
		if realIssuer == credOwner {
			pubKeyStr, _ := getDIDAutheneKey(proof.VerificationMethod, issuerDoc.Authentication, issuerDoc.PublicKey)
			if pubKeyStr == "" {
				return errors.New("DID NOT FIND PUBLIC KEY OF VerificationMethod")
			}
			issuerPublicKey = base58.Decode(pubKeyStr)
		} else {
			////realIssuer is other  and Issuer is not ""
			if issuerPublicKey, err = getAuthenPublicKeyByID(evm, realIssuer, proof.VerificationMethod, isDID); err != nil {
				return err
			}
		}
	}else{
		//customizd id
		issuerLower := strings.ToLower(realIssuer)

		issuerDoc, err = GetIDLastDoc(evm, issuerLower)
		if err != nil {
			log.Error("checkIDVerifiableCredential the GetIDLastDoc ", "err", err)
			return err
		}
		//is self
		ctrlInvalid, err :=checkCustDIDInvalid(evm,realIssuer, proof.VerificationMethod, issuerDoc.Controller)
		if  err!= nil{
			log.Error("checkIDVerifiableCredential","err", err)
			return err
		}
		if ctrlInvalid {
			log.Error("checkIDVerifiableCredential the VerificationMethod controller is invalid")
			return errors.New(" the VerificationMethod controller is invalid")
		}
		if realIssuer == credOwner {
			pubKeyStr, _ :=getCustDIDAuthenKey(evm,proof.VerificationMethod, issuerDoc.PublicKey, issuerDoc.Authentication, issuerDoc.Controller)
			if pubKeyStr == "" {
				return errors.New("DID NOT FIND PUBLIC KEY OF VerificationMethod")
			}
			issuerPublicKey = base58.Decode(pubKeyStr)
		}else{
			//realIssuer is other  customizdid
			if issuerPublicKey, err = getAuthenPublicKeyByID(evm, realIssuer, proof.VerificationMethod, isDID); err != nil {
				return err
			}
		}
	}

	if issuerCode, err = did.GetCodeByPubKey(issuerPublicKey); err != nil {
		return err
	}
	//get signature
	if signature, err = base64url.DecodeString(proof.Signature); err != nil {
		return err
	}
	//if DID is compact format must Completion DID
	credential.CompleteCompact(credOwner)
	// verify proof
	var success bool

	fmt.Println("VerifiableCredentialData:", string(credential.VerifiableCredentialData.GetData()))
	fmt.Println("issuerPublicKey:", base58.Encode(issuerPublicKey))
	fmt.Println("proof.Signature:", proof.Signature)
	success, err = did.VerifyByVM(credential.VerifiableCredentialData, issuerCode, signature)
	if err != nil {
		return err
	}
	if !success {
		return errors.New("[VM] Check Sig FALSE")
	}
	return nil
}


// issuerDID can be did or customizeDID
func getAuthenPublicKeyByID(evm *EVM, issuerID, verificationMethod string, isDID bool) ([]byte, error) {
	var publicKey []byte
	var txData *did.DIDTransactionData
	var err error
	if !isDID{
		issuerID = strings.ToLower(issuerID)
	}
	if txData, err = GetLastDIDTxData(evm, issuerID); err != nil {
		return nil, err
	}

	if txData == nil {
		return []byte{}, errors.New("issuerID is not registered")
	} else {
		Doc := txData.Operation.DIDDoc
		pubKeyStr := ""
		if isDID {
			pubKeyStr, err = getDIDAutheneKey(verificationMethod, Doc.Authentication, Doc.PublicKey)
		} else {
			pubKeyStr, err =	getCustDIDAuthenKey(evm, verificationMethod, Doc.PublicKey, Doc.Authentication, Doc.Controller)
		}
		if err != nil {
			return []byte{}, err
		}
		if pubKeyStr == "" {
			return []byte{}, errors.New("getAuthenPublicKeyByID pubKeyStr is empty")
		}
		publicKey = base58.Decode(pubKeyStr)
	}
	return publicKey, nil
}

func IsLetterOrNumber(s string) bool {
	isLetterOrNumber := regexp.MustCompile(`^[a-zA-Z0-9]+$`).MatchString
	return isLetterOrNumber(s)
}

// checkCu
func checkCustIDOverMaxExpireHeight(evm *EVM,custID, operation string)error{
	lowID := strings.ToLower(custID)
	//
	idKey := []byte(lowID)
	expiredHeight, err := evm.StateDB.GetDIDExpiresHeight(idKey)
	if err != nil {
		//real error happens.return.
		if err.Error() != ErrLeveldbNotFound.Error() && err.Error() != ErrNotFound.Error() {
			return  err
		}
		//only not found can go to next step
	}else{
		//customizedid already created
		expiresHeightInt :=new(big.Int).SetUint64(uint64(expiredHeight))
		nextRegisterTime  := new(big.Int).Add(expiresHeightInt, evm.chainConfig.MaxExpiredHeight)
		//not reached max expired hegith
		if evm.BlockNumber.Cmp(nextRegisterTime) <= 0 {
			//can not be create
			if operation == did.Create_DID_Operation{
				return errors.New("customizedid was already created")
			}
			//for update or transfer
			// if one is deactive
			if isIDDeactive(evm,lowID) {
				return errors.New("ID is already deactivated")
			}
		}else{
			//	over max expired height
			if operation!= did.Create_DID_Operation{
				return errors.New("customizedid was already reached max expired time .Create it again")
			}
		}
	}
	return nil
}

func checkCustomizedDID(evm *EVM, customizedDIDPayload *did.DIDPayload, gas uint64) error {
	if spv.SpvService == nil && didParam.IsTest != true {
		return errors.New("spv.SpvService == nil && didParam.IsTest != true")
	}
	doc := customizedDIDPayload.DIDDoc
	if err := checkCustIDOverMaxExpireHeight(evm, doc.ID, customizedDIDPayload.Header.Operation); err != nil {
		return err
	}


	if err := checkCustomIDPayloadSyntax(customizedDIDPayload, evm); err != nil {
		log.Error("checkPayloadSyntax error", "error", err, "ID", customizedDIDPayload.DIDDoc.ID)
		return err
	}
	// check Custom ID available?
	idString := did.GetDIDFromUri(customizedDIDPayload.DIDDoc.ID)
	if idString == ""{
		return errors.New("customizedid is empty str")
	}
	// check idstring
	if !IsLetterOrNumber(idString) {
		return errors.New("invalid custom ID: only letter and number is allowed")
	}
	if err := checkCustomizedDIDAvailable(customizedDIDPayload); err != nil {
		return err
	}

	//fee := gas * evm.GasPrice.Uint64()
	//if err := checkCustomizedDIDTxFee(customizedDIDPayload, fee); err != nil {
	//	return err
	//}
	//var err error

	//DIDDoc.Expires less than block time
	if err := checkExpires(customizedDIDPayload.DIDDoc.Expires, evm.Time); err != nil {
		return  err
	}
	//if this customized did is already exist and not expired more than 1 year operation should not be create
	//if this customized did is not exist operation should not be update
	if err := checkCustomizedDIDOperation(evm, &customizedDIDPayload.Header,
		customizedDIDPayload.DIDDoc.ID); err != nil {
		return err
	}

	//check payload VerificationMethod
	publicKey , err := getCustDIDAuthenKey(evm, customizedDIDPayload.Proof.VerificationMethod, doc.PublicKey,
		doc.Authentication, doc.Controller)
	if err != nil {
		return err
	}
	if publicKey == ""{
		return errors.New("not find propoer publickey for payload proof")
	}

	if err := checkCustomIDOuterProof(evm, customizedDIDPayload); err != nil {
		return err
	}

	M := 1
	multisignStr := doc.MultiSig
	if multisignStr != "" {
		M, _, err = GetMultisignMN(multisignStr)
		if err != nil {
			return err
		}
	}
	// check ticket when operation is 'Transfer'
	if customizedDIDPayload.Header.Operation == did.Transfer_DID_Operation {
		buf := new(bytes.Buffer)
		lowerID := strings.ToLower(doc.ID)
		buf.WriteString(lowerID)
		fmt.Println("lowerID ########")
		lastTx, err := evm.StateDB.GetLastDIDTxData(buf.Bytes(), evm.chainConfig)
		if err != nil {
			fmt.Println("lowerID ######## not find")

			return err
		}
		m := 1
		if lastTx.Operation.DIDDoc.MultiSig != "" {
			m, _, err = GetMultisignMN(lastTx.Operation.DIDDoc.MultiSig)
			if err != nil {
				return err
			}
		}
		if err := checkTicketAvailable(evm, customizedDIDPayload,
			doc.ID, lastTx.TXID, m, lastTx.Operation.DIDDoc); err != nil {
			return err
		}
	}

	//2,Proof VerificationMethod must be in DIDDoc Authentication or
	//is come from controller
	//getDocProof
	DIDProofArray, err := getDocProof(customizedDIDPayload.DIDDoc.Proof)
	if err != nil {
		return err
	}

	if err = sortDocSlice(doc); err != nil {
		return err
	}
	//4, proof multisign verify
	err = checkCustomIDInnerProof(evm, customizedDIDPayload.DIDDoc.ID, DIDProofArray,
		customizedDIDPayload.DIDDoc.DIDPayloadData, M, doc)
	if err != nil {
		return err
	}
	fmt.Println("checkCustomizedDID all done")
	return nil

}
//
//is expired id can be did or custid
func isControllerExpired(evm *EVM, id string )(bool, error)  {
	//did = strings.ToLower(did)
	id1 := []byte(id)
	expiresHeight, err := evm.StateDB.GetDIDExpiresHeight(id1)
	log.Debug("isControllerExpired", "id", id, "expiresHeight", expiresHeight)
	if err != nil {
		fmt.Println("isControllerExpired did ", id)
		fmt.Println("isControllerExpired", err)
		return true ,err
	}
	expiresHeightInt :=new(big.Int).SetUint64(uint64(expiresHeight))
	if evm.BlockNumber.Cmp(expiresHeightInt) > 0 {
		return true ,nil
	}
	return false, nil
}

//expired or deactived
func isIDDeactive(evm *EVM, id string )bool  {
	return evm.StateDB.IsIDDeactivated(id)
}

//expired or deactived
func isControllerInvalid(evm *EVM, id string )(bool, error)  {
	result , err := isControllerExpired(evm,id)
	if result || err != nil {
		return  result , err
	}
	result = isIDDeactive(evm,id)
	return  result , nil
}

//3, proof multisign verify
func checkDIDInnerProof(evm *EVM, ID string, DIDProofArray []*did.DocProof, iDateContainer interfaces.IDataContainer,
	N int, verifyDoc *did.DIDDoc) error {

	verifyOkCount := 0
	//3, proof multisign verify
	for _, CustomizedDIDProof := range DIDProofArray {
		//get  public key

		publicKeyBase58, _ := getDIDDefaultKey(ID, CustomizedDIDProof.Creator, verifyDoc.Authentication, verifyDoc.PublicKey)
		if publicKeyBase58 == "" {
			return errors.New("checkDIDInnerProof Not find proper publicKeyBase58")
		}
		//get code
		//var publicKeyByte []byte
		publicKeyByte := base58.Decode(publicKeyBase58)

		//var code []byte
		code, err := did.GetCodeByPubKey(publicKeyByte)
		if err != nil {
			return err
		}
		signature, _ := base64url.DecodeString(CustomizedDIDProof.SignatureValue)

		var success bool

		fmt.Println("checkDIDInnerProof data ", string(iDateContainer.GetData()))
		fmt.Println("checkDIDInnerProof publicKeyBase58 ",publicKeyBase58)
		fmt.Println("checkDIDInnerProof CustomizedDIDProof.SignatureValue", CustomizedDIDProof.SignatureValue)


		success, err = did.VerifyByVM(iDateContainer, code, signature)
		if err != nil {
			return err
		}
		if !success {
			return errors.New("checkDIDInnerProof [VM] Check Sig FALSE")
		}
		verifyOkCount++
	}
	if verifyOkCount < N {
		return errors.New("[VM] Check Sig FALSE verifyOkCount < N")
	}
	return nil
}

//3, proof multisign verify
func checkCustomIDInnerProof(evm *EVM, ID string, DIDProofArray []*did.DocProof, iDateContainer interfaces.IDataContainer,
	M int, verifyDoc *did.DIDDoc) error {
	verifyOkCount := 0
	//3, proof multisign verify
	for _, CustomizedDIDProof := range DIDProofArray {
		//get  public key
		publicKeyBase58, _ :=getCustDIDDefKey(evm, CustomizedDIDProof.Creator,  verifyDoc.Controller)
		if publicKeyBase58 == "" {
			return errors.New("checkCustomIDInnerProof Not find proper publicKeyBase58")
		}
		//get code
		//var publicKeyByte []byte
		publicKeyByte := base58.Decode(publicKeyBase58)

		//var code []byte
		code, err := did.GetCodeByPubKey(publicKeyByte)
		if err != nil {
			return err
		}
		signature, _ := base64url.DecodeString(CustomizedDIDProof.SignatureValue)

		var success bool
		fmt.Println("checkDIDInnerProof publicKeyBase58 ", publicKeyBase58)
		fmt.Println("checkDIDInnerProof signature ", CustomizedDIDProof.SignatureValue)
		fmt.Println("checkDIDInnerProof data ", string(iDateContainer.GetData()))

		success, err = did.VerifyByVM(iDateContainer, code, signature)

		if err != nil {
			return err
		}
		if !success {
			return errors.New("checkCustomIDInnerProof Check Sig FALSE")
		}
		verifyOkCount++
	}
	if verifyOkCount < M {
		return errors.New("checkCustomIDInnerProof Check Sig FALSE verifyOkCount < M")
	}
	return nil
}

func checkTicketAvailable(evm *EVM, cPayload *did.DIDPayload,
	customID string, lastTxHash string, M int, verifyDoc *did.DIDDoc) error {
	if cPayload.Ticket.CustomID != customID {
		return errors.New("invalid ID in ticket")
	}

	// 'to' need exist in controller
	to := cPayload.Ticket.To
	var existInController bool
	if controllerArray, ok := cPayload.DIDDoc.Controller.([]interface{}); ok {
		for _, controller := range controllerArray {
			if controller == to {
				existInController = true
			}
		}
	} else if controller, ok := cPayload.DIDDoc.Controller.(string); ok {
		if controller == to {
			existInController = true
		}
	}
	if !existInController {
		return errors.New("'to' is not in controller")
	}

	// 'to' need exist in proof
	dIDProofArray := make([]*did.DocProof, 0)
	customizedDIDProof := &did.DocProof{}
	existInProof := false
	if err := Unmarshal(cPayload.DIDDoc.Proof, &dIDProofArray); err == nil {
		for _, proof := range dIDProofArray {
			contrID, _ := did.GetController(proof.Creator) // check customID
			if contrID == to {
				existInProof = true
			}
		}

	} else if err := Unmarshal(cPayload.DIDDoc.Proof, customizedDIDProof); err == nil {
		contrID, _ := did.GetController(customizedDIDProof.Creator) // check customID
		if contrID == to {
			existInProof = true
		}
	}
	if !existInProof {
		return errors.New("'to' is not in proof")
	}

	// check transactionID
	if cPayload.Ticket.TransactionID != lastTxHash {
		return errors.New("invalid TransactionID of ticket")
	}

	// check proof
	if err := checkTicketProof(evm, cPayload.Ticket, M, verifyDoc.Controller, cPayload.Ticket.Proof); err != nil {
		fmt.Println("err", err)
		return errors.New("invalid proof of ticket")
	}

	return nil
}

func checkTicketProof(evm *EVM, ticket *did.CustomIDTicket, N int,
	lastDocCtrl , ticketProof interface{}) error {

	ticketProofArray, err := getTicketProof(ticketProof)
	if err != nil {
		return err
	}

	err = checkCustomIDTicketProof(evm, ticketProofArray, ticket.CustomIDTicketData, N, lastDocCtrl)
	if err != nil {
		return err
	}

	return nil
}

func checkCustomIDTicketProof(evm *EVM, ticketProofArray []*did.TicketProof, iDateContainer interfaces.IDataContainer,
	M int, lastDocCtrl interface{}) error {
	//isRegistDID := did.IsDID(verifyDoc.ID, verifyDoc.PublicKey)
	verifyOkCount := 0
	//3, proof multisign verify
	for _, ticketProof := range ticketProofArray {
		publicKeyBase58 , err := getCustDIDDefKey(evm, ticketProof.VerificationMethod, lastDocCtrl)
		if publicKeyBase58 == "" || err != nil{
			return errors.New("checkCustomIDTicketProof Not find proper publicKeyBase58")
		}

		//get code
		//var publicKeyByte []byte
		publicKeyByte := base58.Decode(publicKeyBase58)

		//var code []byte
		code, err := did.GetCodeByPubKey(publicKeyByte)
		if err != nil {
			return err
		}
		signature, _ := base64url.DecodeString(ticketProof.Signature)

		var success bool
		fmt.Println("checkCustomIDTicketProof before VerifyByVM")
		success, err = did.VerifyByVM(iDateContainer, code, signature)
		fmt.Println("checkCustomIDTicketProof publicKeyBase58 ", publicKeyBase58)
		fmt.Println("checkCustomIDTicketProof signature ", ticketProof.Signature)
		fmt.Println("checkCustomIDTicketProof data ", string(iDateContainer.GetData()))
		if err != nil {
			return err
		}
		if !success {
			return errors.New("checkCustomIDTicketProof Check Sig FALSE")
		}
		verifyOkCount++
	}
	if verifyOkCount < M {
		return errors.New("checkCustomIDTicketProof Check Sig FALSE verifyOkCount < M")
	}
	return nil
}

func checkCustomizedDIDTicketProof(evm *EVM, verifyDoc *did.DIDDoc, Proof interface{}) ([]*did.TicketProof,
	error) {
	DIDProofArray := make([]*did.TicketProof, 0)
	CustomizedDIDProof := &did.TicketProof{}
	bDIDProofArray := false
	if err := Unmarshal(Proof, &DIDProofArray); err == nil {
		bDIDProofArray = true
		for _, CustomizedDIDProof = range DIDProofArray {
			if IsVerifMethCustIDDefKey(evm, CustomizedDIDProof.VerificationMethod, verifyDoc.ID,
				verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller) {
				return nil, errors.New("DIDProofArray TicketProof  verification method key is not def key")
			}
		}
	} else if err := Unmarshal(Proof, CustomizedDIDProof); err == nil {
		if IsVerifMethCustIDDefKey(evm, CustomizedDIDProof.VerificationMethod, verifyDoc.ID,
			verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller) {
			return nil, errors.New("TicketProof verification method key is not def key")
		}
	} else {
		//error
		return nil, errors.New("isCustomDocVerifMethodDefKey Invalid Proof type")
	}
	//proof object
	if bDIDProofArray == false {
		DIDProofArray = append(DIDProofArray, CustomizedDIDProof)
	}
	return DIDProofArray, nil
}

func checkCustomIDOuterProof(evm *EVM, txPayload *did.DIDPayload) error {
	//get  public key
	doc := txPayload.DIDDoc
	publicKeyBase58 , err := getCustDIDAuthenKey(evm, txPayload.Proof.VerificationMethod, doc.PublicKey,
		doc.Authentication, doc.Controller)
	if publicKeyBase58 == "" || err != nil{
		return err
	}
	//get code
	//var publicKeyByte []byte
	publicKeyByte := base58.Decode(publicKeyBase58)

	//var code []byte
	code, err := did.GetCodeByPubKey(publicKeyByte)
	if err != nil {
		return err
	}
	signature, _ := base64url.DecodeString(txPayload.Proof.Signature)

	var success bool
	fmt.Println("checkCustomIDOuterProof publicKeyBase58 ", publicKeyBase58)
	fmt.Println("checkCustomIDOuterProof signature ", txPayload.Proof.Signature)
	fmt.Println("checkCustomIDOuterProof data ", string(txPayload.GetData()))
	success, err = did.VerifyByVM(txPayload, code, signature)
	if err != nil {
		return err
	}
	if !success {
		return errors.New("checkCustomIDProof[VM] Check Sig FALSE")
	}
	return nil
}

//	if operation is "create" use now m/n and public key otherwise use last time m/n and public key
func getVerifyDocMultisign(evm *EVM, customizedID string) (*did.DIDDoc, error) {
	buf := new(bytes.Buffer)
	customizedID = strings.ToLower(customizedID)
	buf.WriteString(customizedID)
	transactionData, err := evm.StateDB.GetLastDIDTxData(buf.Bytes(), evm.chainConfig)
	if err != nil {
		return nil, err
	}
	return transactionData.Operation.DIDDoc, nil
}

//get did/cutsomizedid default key
func getDefaultPublicKey(evm *EVM, ID, verificationMethod string, isDID bool,
	publicKey []did.DIDPublicKeyInfo, authentication []interface{}, controller interface{}) (string, error) {
	if isDID {
		return getDIDDefaultKey(ID, verificationMethod, authentication, publicKey)
	} else {
		return getCustDIDDefKey(evm, verificationMethod,  controller)
	}
}

func ReserveCustomToLower(reservedCustomIDs map[string]struct{})map[string]struct{}{
	lowerCustomIDs := make(map[string]struct{}, 0)
	for id,_ := range reservedCustomIDs{
		lowerCustomIDs[strings.ToLower(id)] =struct{}{}
	}
	return	lowerCustomIDs
}

func ReceivedCustomToLower(receivedCustomIDs map[string]common.Uint168)map[string]common.Uint168{
	lowerCustomIDs := make(map[string]common.Uint168, 0)
	for id, v := range receivedCustomIDs{
		lowerCustomIDs[strings.ToLower(id)] =v
	}
	return	lowerCustomIDs
}

func checkCustomizedDIDAvailable(cPayload *did.DIDPayload) error {

	log.Error("checkCustomizedDIDAvailable 1")
	if spv.SpvService == nil && didParam.IsTest == true {
		return nil
	}
	if  spv.SpvService == nil{
		return nil
	}
	bestHeader,err := spv.SpvService.HeaderStore().GetBest()
	if err != nil{
		return err
	}
	reservedCustomIDs, err := spv.SpvService.GetReservedCustomIDs(bestHeader.Height)
	if err != nil {
		return err
	}
	receivedCustomIDs, err := spv.SpvService.GetReceivedCustomIDs(bestHeader.Height)
	if err != nil {
		return err
	}

	if reservedCustomIDs == nil || len(reservedCustomIDs) == 0 {
		return errors.New("Before registe customized did must have reservedCustomIDs")
	}
	reservedCustomIDs = ReserveCustomToLower(reservedCustomIDs)
	receivedCustomIDs = ReceivedCustomToLower(receivedCustomIDs)
	log.Error("checkCustomizedDIDAvailable ", "reservedCustomIDs", reservedCustomIDs)
	log.Error("checkCustomizedDIDAvailable ", "receivedCustomIDs ", receivedCustomIDs)

	noPrefixID := did.GetDIDFromUri(cPayload.DIDDoc.ID)
	//customID is no prefix and lower character
	customID := strings.ToLower(noPrefixID)
	log.Error("checkCustomizedDIDAvailable 1", "customID", customID, "noPrefixID", noPrefixID)

	if _, ok := reservedCustomIDs[customID]; ok {
		if customDID, ok := receivedCustomIDs[customID]; ok {
			rcDID, err := customDID.ToAddress()
			if err != nil {
				return errors.New("invalid customDID in db")
			}
			if id, ok := cPayload.DIDDoc.Controller.(string); ok {
				if !strings.Contains(id, rcDID) {
					return errors.New("invalid controller did")
				}
			} else {
				// customID need be one of the controller.
				var controllerCount int
				if dids, ok := cPayload.DIDDoc.Controller.([]interface{}); ok {
					for _, did := range dids {
						if strings.Contains(did.(string), rcDID){
							controllerCount++
						}
					}
				} else {
					return errors.New("invalid controller")
				}
				if controllerCount != 1 {
					return errors.New("not in controller")
				}
				// customID need be one oof the signature
				dIDProofArray := make([]*did.DocProof, 0)
				customizedDIDProof := &did.DocProof{}
				//	var invalidProofCount int
				if err := Unmarshal(cPayload.DIDDoc.Proof, &dIDProofArray); err == nil {
					invalidProofCount := 0
					for _, proof := range dIDProofArray {
						if strings.Contains(proof.Creator, rcDID) {
							invalidProofCount++
						}
					}
					if invalidProofCount == 0 {
						return errors.New("there is no signature of custom ID")
					} else if invalidProofCount > 1 {
						return errors.New("there is duplicated signature of custom ID")
					}
				} else if err := Unmarshal(cPayload.DIDDoc.Proof, customizedDIDProof); err == nil {
					contrID, _ := did.GetController(customizedDIDProof.Creator) // check customID
					if !strings.Contains(contrID, rcDID) {
						return errors.New("there is no signature of custom ID")
					}
				} else {
					return errors.New("invalid Proof type")
				}
			}
		}else{
			return errors.New("customID was already reserved ")
		}
	}

	return nil
}

//check operateion create---->db must not have
//                 update----->db must have
func checkCustomizedDIDOperation(evm *EVM, header *did.Header,
	customizedDID string) error {
	buf := new(bytes.Buffer)
	lowCustomDID := strings.ToLower(customizedDID)
	buf.WriteString(lowCustomDID)
	lastTXData, err := evm.StateDB.GetLastDIDTxData(buf.Bytes(), evm.chainConfig)

	dbExist := true
	if err != nil {
		if err.Error() == ErrLeveldbNotFound.Error() || err.Error() == ErrNotFound.Error() {
			dbExist = false
		} else {
			return err
		}
	}
	if dbExist {
		if header.Operation == did.Create_DID_Operation {
			id1 := []byte(lowCustomDID)
			expiresHeight, err := evm.StateDB.GetDIDExpiresHeight(id1)
			if err != nil{
				return err
			}
			configHeight := big.NewInt( 0)
			targetHeight := configHeight.Add(configHeight, big.NewInt(int64(expiresHeight)))
			if evm.Context.BlockNumber.Cmp(targetHeight) < 0 {
				//check if this customized id is expired over 1 year
				return errors.New("Customized DID WRONG OPERATION ALREADY EXIST")
			}

		} else if header.Operation == did.Update_DID_Operation {
			//check PreviousTxid
			hash, err := common.Uint256FromHexString(header.PreviousTxid)
			if err != nil {
				return err
			}
			preTXID := hash.String()

			configHeight := evm.chainConfig.OldDIDMigrateHeight
			if evm.Context.BlockNumber.Cmp(configHeight) > 0 {
				if lastTXData.TXID != preTXID {
					return errors.New("Customized DID PreviousTxid IS NOT CORRECT")
				}
			}
		}
	} else {
		if header.Operation == did.Update_DID_Operation {
			return errors.New("Customized DID WRONG OPERATION NOT EXIST")
		}
	}
	return nil
}

//is VerificationMethod CustomizedID DefaultKey
func IsVerifMethCustIDDefKey(evm *EVM, VerificationMethod, ID string,
	publicKey []did.DIDPublicKeyInfo, authentication []interface{}, Controller interface{}) bool {
	controllerVM, _ := GetDIDAndUri(VerificationMethod)

	//1, check is proofUriSegment public key in authentication. if it is in then check done
	if controllerVM == "" || controllerVM == ID {
		var pubkeyCount int
		for i := 0; i < len(publicKey); i++ {
			if verificationMethodEqual(VerificationMethod, publicKey[i].ID) {
				id := did.GetDIDFromUri(publicKey[i].ID)
				if !did.IsPublickDIDMatched(publicKey[i].PublicKeyBase58, id) {
					return false
				}
				pubkeyCount++
				break
			}
		}
		if pubkeyCount == 1 {
			return true
		}
	} else {
		IsVerifMethCustIDControllerKey(evm, VerificationMethod, ID, Controller, true)
	}
	return false
}

// keyType default key / authenKey
func IsVerifMethCustIDControllerKey(evm *EVM, VerificationMethod, ID string, Controller interface{},
	isDefaultKey bool) bool {
	controllerVM, _ := GetDIDAndUri(VerificationMethod)
	if controllerArray, bControllerArray := Controller.([]interface{}); bControllerArray == true {
		//2.1 is controller exist
		for _, controller := range controllerArray {
			if controller == controllerVM {
				doc, err := GetIDLastDoc(evm, controllerVM)
				if err != nil {
					return false
				}
				//payload := TranasactionData.Operation.DIDDoc
				// check if VerificationMethod related public key is default key
				pubKeyBase58Str := ""
				if isDefaultKey {
					pubKeyBase58Str, _ = getDefaultPublicKey(evm, ID, VerificationMethod, true, doc.PublicKey,
						doc.Authentication, doc.Controller)
				} else {
					pubKeyBase58Str, _ = getAuthenPublicKey(evm, VerificationMethod, true, doc.PublicKey,
						doc.Authentication, doc.Controller)
				}

				if pubKeyBase58Str == "" {
					return false
				}
				return true

			}
		}
	} else if controller, bController := Controller.(string); bController == true {
		if controller == controllerVM {
			//get controllerDID last store data
			doc, err := GetIDLastDoc(evm, controllerVM)
			if err != nil {
				return false
			}
			pubKeyBase58Str, _ := getDefaultPublicKey(evm, controller, VerificationMethod, true, doc.PublicKey,
				doc.Authentication, doc.Controller)
			if pubKeyBase58Str == "" {
				return false
			}
			return true
		}
	}
	return false
}

func GetDIDAndUri(idURI string) (string, string) {
	index := strings.LastIndex(idURI, "#")
	if index == -1 {
		return "", ""
	}
	return idURI[:index], idURI[index:]
}

func getTicketProof(Proof interface{}) ([]*did.TicketProof, error) {
	DIDProofArray := make([]*did.TicketProof, 0)

	//var CustomizedDIDProof id.DocProof
	CustomizedDIDProof := &did.TicketProof{}
	//var bExist bool
	if err := Unmarshal(Proof, &DIDProofArray); err == nil {
	} else if err := Unmarshal(Proof, CustomizedDIDProof); err == nil {
		DIDProofArray = append(DIDProofArray, CustomizedDIDProof)
	} else {
		//error
		return nil, errors.New("isCustomDocVerifMethodDefKey Invalid Proof type")
	}
	return DIDProofArray, nil
}

func getDocProof(Proof interface{}) ([]*did.DocProof, error) {
	DIDProofArray := make([]*did.DocProof, 0)

	//var CustomizedDIDProof id.DocProof
	CustomizedDIDProof := &did.DocProof{}
	//var bExist bool
	if err := Unmarshal(Proof, &DIDProofArray); err == nil {
	} else if err := Unmarshal(Proof, CustomizedDIDProof); err == nil {
		DIDProofArray = append(DIDProofArray, CustomizedDIDProof)
	} else {
		//error
		return nil, errors.New("isCustomDocVerifMethodDefKey Invalid Proof type")
	}
	return DIDProofArray, nil
}


//is doc proof customizedid Creator default key
func isCustomDocVerifMethodDefKey(evm *EVM, lastDocCtrl, Proof interface{}) bool {
	//2,Proof VerificationMethod must be in DIDDoc Authentication or
	//is come from controller
	//var DIDProofArray []*id.DocProof
	DIDProofArray := make([]*did.DocProof, 0)
	//var CustomizedDIDProof id.DocProof
	CustomizedDIDProof := &did.DocProof{}
	//var bExist bool

	if err := Unmarshal(Proof, &DIDProofArray); err == nil {
		for _, CustomizedDIDProof = range DIDProofArray {
			publicKey , err := getCustDIDDefKey(evm, CustomizedDIDProof.Creator, lastDocCtrl)
			if publicKey == "" || err != nil{
				return false
			}
		}
	} else if err := Unmarshal(Proof, CustomizedDIDProof); err == nil {
		publicKey , err :=getCustDIDDefKey(evm, CustomizedDIDProof.Creator, lastDocCtrl)
		if publicKey == "" || err != nil{
			return false
		}
	} else {
		return false
	}

	return true
}


func GetMultisignMN(mulstiSign string) (int, int, error) {
	index := strings.LastIndex(mulstiSign, ":")
	if index == -1 {
		return 0, 0, errors.New("mulstiSign did not have :")
	}
	M, err := strconv.Atoi(mulstiSign[0:index])
	if err != nil {
		return 0, 0, err
	}
	N, err := strconv.Atoi(mulstiSign[index+1:])
	if err != nil {
		return 0, 0, err
	}
	return M, N, nil
}

//Payload
//ID  Expires  Controller Operation Payload interface
func getIDTxFee(evm *EVM, customID, expires, operation string, controller interface{}, payloadLen int) float64 {
	//lengthRate id lenght lengthRate
	lengthRate := getCustomizedDIDLenFactor(customID)

	//lifeRate Valid period lifeRate
	stamp := time.Unix(evm.Time.Int64(), 0)
	lifeRate := getValidPeriodFactor(expires, stamp)
	//OperationRate operation create or update OperationRate
	OperationRate := getOperationFactor(operation)
	//multisigRate controller sign number multisigRate
	multisigRate := getControllerFactor(controller)
	//sizeRate doc size sizeRate
	sizeRate := getSizeFactor(payloadLen)
	//CustomIDFeeRate factor got from cr proposal
	CustomIDFeeRate := didParam.CustomIDFeeRate
	if spv.SpvService != nil {
		feeRate, _ := spv.SpvService.GetRateOfCustomIDFee(uint32(evm.BlockNumber.Uint64()))
		log.Debug("getIDTxFee  "," feeRate ", feeRate)
		if feeRate != 0 {
			CustomIDFeeRate = feeRate
		}
	}
	fmt.Printf("#### Printf getIDTxFee lengthRate %.16f lifeRate%.16f OperationRate %.16f multisigRate%.16f sizeRate%.16f CustomIDFeeRate %.16f",
		lengthRate, lifeRate, OperationRate, multisigRate, sizeRate, float64(CustomIDFeeRate))
	fee := (lengthRate*lifeRate*OperationRate*sizeRate + multisigRate) * float64(CustomIDFeeRate)
	return fee
}

func getCustomizedDIDLenFactor(ID string) float64 {
	len := len(ID)
	var lengthRate float64
	if len == 0 {
		return 0.3
	} else if len == 1 {
		lengthRate= 6400
	} else if len == 2 {
		return 3200
	} else if len == 3 {
		return 1200
	} else if len <= 32 {
		//100 - [(n-1) / 8 ]
		lengthRate= 100 - float64((len-1)/8)
	} else if len <= 64 {
		//93 + [(n-1) / 8 ]
		lengthRate= 93 + float64((len-1)/8)
	} else {
		//100 * (n-59) / 3
		lengthRate= 100 * ((float64(len) - 59) / 2)
	}
	if lengthRate < 0 {
		lengthRate = 0
	}
	return  lengthRate
}

func getDays(t1, t2 time.Time) int64 {
	t1Unix := t1.Unix()
	t2Unix := t2.Unix()
	return (t1Unix - t2Unix) / (24 * 3600)
}

func getValidPeriodFactor(Expires string, nowTime time.Time) float64 {
	expiresTime, _ := time.Parse(time.RFC3339, Expires)
	days := getDays(expiresTime, nowTime)
	if days <0 {
		days = 0
	}
	if days < 180 {
		days += 180
	}
	years := float64(days) / 365

	lifeRate := float64(0)
	if years < 1 {
		lifeRate = years * ((100 - (3 * math.Log2(1))) / 100)
	} else {
		lifeRate = years * ((100 - (3 * math.Log2(years))) / 100)
	}
	if lifeRate <0 {
		lifeRate = 0
	}
	return lifeRate

}

func getOperationFactor(operation string) float64 {
	factor := float64(0)
	switch operation {
	case "create":
		factor = 1
	case "update":
		factor = 0.8
	case "transfer":
		factor = 1.2
	case "deactivate":
		factor = 0.3
	case "declare":
		factor = 1
	case "revoke":
		factor = 0.3
	default:
		factor = 1
	}
	return factor
}

func getSizeFactor(payLoadSize int) float64 {
	factor := float64(0)
	if payLoadSize <= 1024 {
		factor = 1
	} else if payLoadSize <= 32*1024 {
		factor = math.Log10(float64(payLoadSize)/1024)/2 + 1
	} else {
		factor = math.Pow(float64(payLoadSize)/1024, 0.9)*math.Log10(float64(payLoadSize)/1024) - 33.4
	}
	if factor <0  {
		factor = 0
	}
	return factor
}

func getControllerFactor(controller interface{}) float64 {
	if controller == nil {
		return 0
	}
	if controllerArray, bControllerArray := controller.([]interface{}); bControllerArray == true {
		controllerLen := len(controllerArray)
		if controllerLen <= 1 {
			return float64(controllerLen)
		}
		//M=2**(m+3)
		return math.Pow(2, float64(controllerLen+3))
	}
	return 1

}

func isCustomizeDIDExist(evm *EVM,ID string)(bool,error){
	lowerID := strings.ToLower(ID)
	fmt.Println("lowerID", lowerID)
	isDID, err := evm.StateDB.IsDID(lowerID)
	if err != nil {
		return false, err
	}
	return !isDID, nil
}

//if controller is unique return  controllers and nil
//else return nil and error
func checkDeactivePayloadVM(controller           interface{}, verificationMethod string )error{
	prefixDID,_ := GetDIDAndUri(verificationMethod)
	//if is controller array
	if controllerArray, ok := controller.([]interface{}); ok {
		for _, controller := range controllerArray {
			contrl := controller.(string)
			if contrl == prefixDID{
				return nil
			}
		}
	}else{
		contrl := controller.(string)
		if contrl == prefixDID{
			return nil
		}
	}
	return errors.New("checkDeactivePayloadVM verificationMethod is not belong to controller")
}

func isDID(evm *EVM, ID string)(bool, error){
	ret, err := evm.StateDB.IsDID(ID)
	//fmt.Println("checkDeactivateDID ID", ID)
	if err!= nil {
		if err.Error() == ErrLeveldbNotFound.Error() || err.Error() == ErrNotFound.Error()  {
			//custDID
			_, err := isCustomizeDIDExist(evm, ID)
			if err != nil {
				return false, err
			}
			ret = false
		}else{
			return false, err
		}
	}
	return  ret, nil
}

func checkDeactivateDID(evm *EVM, deactivateDIDOpt *did.DIDPayload) error {
	ID := deactivateDIDOpt.Payload
	// Who wants to be deactived did or customizedid
	isDID, err := evm.StateDB.IsDID(ID)
	//fmt.Println("checkDeactivateDID ID", ID)
	if err!= nil {
		if err.Error() == ErrLeveldbNotFound.Error() || err.Error() == ErrNotFound.Error()  {
			//custDID
			_, err := isCustomizeDIDExist(evm, ID)
			if err != nil {
				return err
			}
			isDID = false
		}else{
			return err
		}
	}

	//customizedid
	if !isDID {
		ID = strings.ToLower(ID)
	}


	buf := new(bytes.Buffer)
	buf.WriteString(ID)
	lastTXData, err := evm.StateDB.GetLastDIDTxData(buf.Bytes(), evm.chainConfig)
	if err != nil {
		return err
	}
	//customizedid
	if!isDID{
		//check deactivateDIDOpt.Proof.VerificationMethod must one of the controller
		ctrl := lastTXData.Operation.DIDDoc.Controller
		if err := checkDeactivePayloadVM(ctrl,deactivateDIDOpt.Proof.VerificationMethod); err != nil{
			return err
		}
	}


	//todo verify everycontroller must valid
	//do not deactivage a did who was already deactivate
	if evm.StateDB.IsIDDeactivated(ID) {
		return errors.New("DID WAS AREADY DEACTIVE")
	}

	prefixDID,_ := GetDIDAndUri(deactivateDIDOpt.Proof.VerificationMethod)
	ctrlInvalid, err := isControllerInvalid(evm,prefixDID)
	if  err!= nil{
		return err
	}

	if ctrlInvalid {
		return errors.New(" the VerificationMethod controller is invalid")
	}

	//get  public key getAuthorizatedPublicKey
	//getDeactivatePublicKey
	didDoc := lastTXData.Operation.DIDDoc
	publicKeyBase58 := ""
	if isDID {
		publicKeyBase58, _ = getDIDDeactivateKey(ID, deactivateDIDOpt.Proof.VerificationMethod,  didDoc.Authentication,
		 	didDoc.PublicKey,didDoc.Authorization)
	} else {
		// customizedid use default key not authorization key
		publicKeyBase58, _ =getCustDIDDefKey(evm, deactivateDIDOpt.Proof.VerificationMethod,  didDoc.Controller)
	}
	if publicKeyBase58 == "" {
		return errors.New("Not find the publickey of verificationMethod")
	}

	//get code
	//var publicKeyByte []byte
	publicKeyByte := base58.Decode(publicKeyBase58)

	//var code []byte
	code, err := did.GetCodeByPubKey(publicKeyByte)
	if err != nil {
		return err
	}
	signature, _ := base64url.DecodeString(deactivateDIDOpt.Proof.Signature)

	var success bool
	//paylaod proof
	fmt.Println("checkDeactivateDID publicKeyBase58 ", publicKeyBase58)
	fmt.Println("checkDeactivateDID signature ", deactivateDIDOpt.Proof.Signature)
	fmt.Println("checkDeactivateDID data ", string(deactivateDIDOpt.GetData()))
	success, err = did.VerifyByVM(deactivateDIDOpt, code, signature)
	if err != nil {
		return err
	}
	if !success {
		return errors.New("checkDeactivateDID Check Sig FALSE")
	}
	return nil
}

//get did/cutsomizedid deactivate public key
//for did include default key + authorization key
//for customizedID controller default key
/*
verificationMethod: did/customizedID uni public string
isRegistDID: true is did and  false is customizedID
publicKey: public keys
authentication: authentication
authorization: authorization
controller controller
*/
func getDeactivatePublicKey(evm *EVM, ID, verificationMethod string, isDID bool,
	publicKey []did.DIDPublicKeyInfo, authentication []interface{}, authorization []interface{},
	controller interface{}) (string, error) {

	if isDID {
		return getDIDDeactivateKey(ID, verificationMethod, authentication, publicKey, authorization)
	} else {
		// customizedid use default key not authorization key
		return getCustomizedIDPublicKey(evm, verificationMethod, nil, nil, controller, DefaultPublicKey)
	}
}

func checkCredentialTX(evm *EVM, payload *did.DIDPayload) error {
	if payload.Header.Operation == did.Declare_Verifiable_Credential_Operation {
		if payload.CredentialDoc == nil || payload.CredentialDoc.VerifiableCredential == nil{
			return  errors.New("payload.CredentialDoc == nil || payload.CredentialDoc.VerifiableCredential")
		}
		_, err := time.Parse(time.RFC3339, payload.CredentialDoc.ExpirationDate)
		if err != nil {
			return errors.New("invalid ExpirationDate")
		}
	}

	switch payload.Header.Operation {
	case did.Declare_Verifiable_Credential_Operation:
		return checkDeclareVerifiableCredential(evm, payload)
	case did.Revoke_Verifiable_Credential_Operation:
		return checkRevokeVerifiableCredential(evm, payload)
	}

	return errors.New("invalid operation")
}

func checkDeclareVerifiableCredential(evm *EVM, payload *did.DIDPayload) error {
	//1, if one credential is declear can not be declear again
	//if one credential is revoke  can not be decalre or revoke again
	// this is the receiver id  todo
	if err := checkExpires(payload.CredentialDoc.VerifiableCredential.ExpirationDate, evm.Time); err != nil {
		return  err
	}

	credOwner := GetCredentialOwner(payload.CredentialDoc.CredentialSubject)
	credentialID := payload.CredentialDoc.ID
	issuer := getCredentialIssuer(credOwner, payload.CredentialDoc.VerifiableCredential)
	if err := checkVerifiableCredentialOperation(evm, &payload.Header, credentialID,  issuer); err != nil {
		return err
	}


	return checkIDVerifiableCredential(evm, credOwner, payload)
}


//1, if one credential is declear can not be declear again
//if one credential is revoke  can not be decalre or revoke again
func checkVerifiableCredentialOperation(evm *EVM, header *did.Header,
	CredentialID , issuer string) error {
	if header.Operation != did.Declare_Verifiable_Credential_Operation {
		return errors.New("checkVerifiableCredentialOperation WRONG OPERATION")
	}
	// tod  CredentialID if it is belong to custdid must tolow
	credOwner, uri := did.GetController(CredentialID)
	ownerIsDID, err := isDID(evm,credOwner)
	if err != nil {
		return err
	}
	if !ownerIsDID{
		CredentialID= strings.ToLower(credOwner) +uri
	}
	buf := new(bytes.Buffer)
	buf.WriteString(CredentialID)
	_, err = evm.StateDB.GetCredentialExpiresHeight(buf.Bytes())
	dbExist := true
	if err != nil {
		if err.Error() == ErrLeveldbNotFound.Error() || err.Error() == ErrNotFound.Error() {
			dbExist = false
		} else {
			return err
		}
	}

	if dbExist  {
		return errors.New("VerifiableCredential WRONG OPERATION")
	}else{

		issuerIsDID, err := isDID(evm,issuer)
		if err != nil {
			return err
		}
		//even it is not exit check if it was revoke by owner or issuer
		ctrls, err := evm.StateDB.GetRevokeCredentialCtrls(buf.Bytes())
		if err != nil{
			if err.Error() == ErrLeveldbNotFound.Error() || err.Error() == ErrNotFound.Error()  {
				return nil
			}
			return err
		}
		var ownerTxData *did.DIDTransactionData
		var issuerTxData *did.DIDTransactionData

		if !ownerIsDID {
			if ownerTxData, err = GetLastDIDTxData(evm, strings.ToLower(credOwner)); err != nil {
				return  err
			}
		}
		if !issuerIsDID {
			if issuerTxData, err = GetLastDIDTxData(evm, strings.ToLower(credOwner)); err != nil {
				return  err
			}
		}
		//iterator every ctrl check if owner or issuer have revok this credential
		for _, ctrl := range ctrls{
			if ownerIsDID {
				if ctrl == credOwner {
					return errors.New("VerifiableCredential was revoked by owner")
				}
			}else{
				//check if customizedid owner have ctrl
				if ctrl == credOwner {
					return errors.New("VerifiableCredential was revoked by owner")
				}
				if HaveCtrl(ownerTxData.Operation.DIDDoc.Controller, ctrl) {
					return errors.New("VerifiableCredential was revoked by owner controller")
				}

			}
			if issuerIsDID {
				if ctrl == issuer {
					return errors.New("VerifiableCredential was revoked by issuer")
				}
			}else{
				if ctrl == issuer {
					return errors.New("VerifiableCredential was revoked by issuer")
				}
				//check if customizedid owner have ctrl
				if HaveCtrl(issuerTxData.Operation.DIDDoc.Controller, ctrl) {
					return errors.New("VerifiableCredential was revoked by issuer controller")
				}
			}
		}

	}
	return nil
}

func checkRevokeCustomizedDIDVerifiableCredential(evm *EVM, owner string, issuer string, payload *did.DIDPayload) error {
	//1, if it is "create" use now m/n and public key otherwise use last time m/n and public key
	if err := checkIDVerifiableCredential(evm, owner,payload); err == nil {
		return nil
	}
	if err := checkIDVerifiableCredential(evm, issuer, payload); err == nil {
		return nil
	}

	return errors.New("revoke  checkIDVerifiableCredential failed")
}
//IDS can have did or ctusomizedid
//issuer , owner or someone
//even it is not exit check if it was revoke by owner or issuer
func isRevokedByIDS(evm *EVM,credentID string, IDS []string)(bool,error){
	buf := new(bytes.Buffer)

	credOwner, uri := did.GetController(credentID)
	ownerIsDID, err := isDID(evm,credOwner)
	if err != nil {
		return false, err
	}
	if !ownerIsDID{
		credentID= strings.ToLower(credOwner) +uri
	}
	buf.WriteString(credentID)
	ctrls, err := evm.StateDB.GetRevokeCredentialCtrls(buf.Bytes())
	if err != nil{
		if err.Error() == ErrLeveldbNotFound.Error() || err.Error() == ErrNotFound.Error()  {
			return false, nil
		}
		return false, err
	}

	for _, id := range IDS {
		var idTxData *did.DIDTransactionData
		isDID, err := isDID(evm,id)
		if err != nil {
			return false, err
		}
		if !isDID{
			id= strings.ToLower(id)
		}
		if idTxData, err = GetLastDIDTxData(evm, id); err != nil {
			return  false, err
		}

		for _, ctrl := range ctrls{
			if isDID {
				if ctrl == id {
					return true, nil
				}
			}else{
				//check if customizedid owner have ctrl
				if ctrl == id {
					return true, nil
				}
				if HaveCtrl(idTxData.Operation.DIDDoc.Controller, ctrl) {
					return true, nil
				}

			}
		}
	}
	return false ,nil
}

func checkRevokeVerifiableCredential(evm *EVM, txPayload *did.DIDPayload) error {
	credentialID := txPayload.Payload
	credOwner, uri := did.GetController(credentialID)
	ownerIsDID, err := isDID(evm,credOwner)
	if err != nil {
		return err
	}
	if !ownerIsDID{
		credentialID= strings.ToLower(credOwner) +uri
	}

	buf := new(bytes.Buffer)
	buf.WriteString(credentialID)

	dbExist := false
	_, err = evm.StateDB.GetCredentialExpiresHeight(buf.Bytes())
	//already decalred
	if err != nil {
		if err.Error() == ErrLeveldbNotFound.Error() || err.Error() == ErrNotFound.Error() {
			dbExist = false
		} else {
			return err
		}
	}else{
		dbExist = true
	}

	if dbExist {
		lastTXData, err := evm.StateDB.GetLastVerifiableCredentialTxData(buf.Bytes(), evm.chainConfig)
		//dbExist := true
		if err != nil {
			return err
		}
		if lastTXData == nil {
			return errors.New("checkRevokeVerifiableCredential invalid last transaction")
		}
		// check if owner or issuer send this transaction
		owner := GetCredentialOwner(lastTXData.Operation.CredentialDoc.CredentialSubject)
		issuer := getCredentialIssuer(owner, lastTXData.Operation.CredentialDoc.VerifiableCredential)
		ids  :=[]string{credOwner, issuer}
		// try check if revoked by owner or issuer
		revoked , err :=isRevokedByIDS(evm, credentialID, ids)
		if err != nil {
			return err
		}
		if revoked {
			return errors.New("already have valid revoked")
		}
		return checkRevokeCustomizedDIDVerifiableCredential(evm, owner, issuer, txPayload)
	}else{
		controler ,_ := did.GetController(txPayload.Proof.VerificationMethod)
		ids  :=[]string{credOwner, controler}
		// try check if revoked by owner or issuer
		revoked , err :=isRevokedByIDS(evm, credentialID, ids)
		if err != nil {
			return err
		}
		if revoked {
			return errors.New("already have valid revoked")
		}
		//revoke credentialID who is not exist
		if err := checkIDVerifiableCredential(evm, controler,txPayload); err != nil {
			return err
		}
	}

	return nil
}
//owner can be DID or custid
func getCredentialIssuer(owner string, cridential *did.VerifiableCredential) string {
	realIssuer := cridential.Issuer
	if cridential.Issuer == "" {
		creSub := cridential.CredentialSubject.(map[string]interface{})
		for k, v := range creSub {
			if k == did.ID_STRING {
				realIssuer = v.(string)
				break
			}
		}
		if realIssuer == "" {
			realIssuer = owner
		}
	}
	return realIssuer
}

func GetCredentialOwner(CredentialSubject interface{}) string {
	creSub := CredentialSubject.(map[string]interface{})
	ID := ""
	for k, v := range creSub {
		if k == did.ID_STRING {
			ID = v.(string)
			break
		}
	}
	return ID
}



func checkCustDIDInvalid(evm *EVM, custDID , verificationMethod string, docCtrl           interface{} )(bool, error){
	// singer is customized
	signer  := custDID
	IDSigner := strings.ToLower(signer)
	//make sure signer is valid
	ctrlInvalid, err := isControllerInvalid(evm,IDSigner)
	if  err!= nil{
		log.Error("checkCustDIDInvalid","err", err)
		return true,  err
	}
	if ctrlInvalid {
		log.Error("checkCustDIDInvalid the VerificationMethod controller is invalid")
		return true, errors.New(" checkCustDIDInvalid the VerificationMethod controller is invalid")
	}
	//VerificationMethod can be one of  customized IDSigner controller
	vmController,_ := GetDIDAndUri(verificationMethod)
	//check VerificationMethod's controller invalide
	if vmController  !=  signer{
		//check if signer if one of customdid 's controller
		if ! HaveCtrl(docCtrl, vmController){
			return true, errors.New("VerificationMethod is not equal with signer")
		}
		//make sure VerificationMethod is valid
		ctrlInvalid, err = isControllerInvalid(evm,vmController)
		if  err!= nil{
			log.Error("checkCustDIDInvalid","err", err)
			return true,err
		}
		if ctrlInvalid {
			log.Error("checkCustDIDInvalid the VerificationMethod controller is invalid","vmController", vmController)
			return true, errors.New("checkCustDIDInvalid the VerificationMethod controller is invalid")
		}
	}
	return  false  ,nil
}

//signer can be owner or issuer
//signer can be did/ customizwdid
//credPayload.Proof.VerificationMethod can be did#uri or custid#uri
func checkIDVerifiableCredential(evm *EVM, signer string,
	credPayload *did.DIDPayload) error {
	//1. signer is did o r customizedid
	bDID , err := isDID(evm, signer)
	if err!= nil {
		return err
	}
	// check signer expire  and deactive
	IDSigner := signer
	var verifyDIDDoc*did.DIDDoc
	//
	if bDID {
		//make sure signer is valid
		ctrlInvalid, err := isControllerInvalid(evm,IDSigner)
		if  err!= nil{
			log.Error("checkIDVerifiableCredential","err", err)
			return err
		}
		if ctrlInvalid {
			log.Error("checkIDVerifiableCredential the VerificationMethod controller is invalid")
			return errors.New(" the VerificationMethod controller is invalid")
		}
		verifyDIDDoc, err = GetIDLastDoc(evm, IDSigner)
		if err != nil {
			log.Error("checkIDVerifiableCredential the GetIDLastDoc ", "err", err)
			return err
		}
	}else{
		//// singer is customized
		IDSigner = strings.ToLower(signer)
		verifyDIDDoc, err = GetIDLastDoc(evm, IDSigner)
		if err != nil {
			log.Error("checkIDVerifiableCredential the GetIDLastDoc ", "err", err)
			return err
		}
		ctrlInvalid, err :=checkCustDIDInvalid(evm,signer, credPayload.Proof.VerificationMethod, verifyDIDDoc.Controller)
		if  err!= nil{
			log.Error("checkIDVerifiableCredential","err", err)
			return err
		}
		if ctrlInvalid {
			log.Error("checkIDVerifiableCredential the VerificationMethod controller is invalid")
			return errors.New(" checkIDVerifiableCredential the VerificationMethod controller is invalid")
		}

	}

	publicKeyBase58 := ""
	//todo test this
	//if is did
	if bDID {
		publicKeyBase58, err = getDIDAutheneKey(credPayload.Proof.VerificationMethod, verifyDIDDoc.Authentication, verifyDIDDoc.PublicKey)
	}else{
		//customized did
		publicKeyBase58, err = getCustDIDAuthenKey(evm,credPayload.Proof.VerificationMethod,verifyDIDDoc.PublicKey,
			verifyDIDDoc.Authentication, verifyDIDDoc.Controller)
	}
	if publicKeyBase58 == "" {
		log.Error("checkIDVerifiableCredential checkDIDVerifiableCredential Not find proper publicKeyBase58 ")
		return errors.New("checkDIDVerifiableCredential Not find proper publicKeyBase58")
	}


	//get code
	//var publicKeyByte []byte
	publicKeyByte := base58.Decode(publicKeyBase58)

	//var code []byte
	code, err := did.GetCodeByPubKey(publicKeyByte)
	if err != nil {
		return err
	}
	signature, _ := base64url.DecodeString(credPayload.Proof.Signature)

	var success bool
	//VerifiableCredentials outter(payload) proof
	success, err = did.VerifyByVM(credPayload, code, signature)
	fmt.Println("credPayload.GetData():", string(credPayload.GetData()))
	fmt.Println("publicKeyBase58:", publicKeyBase58)
	fmt.Println("Signature:", credPayload.Proof.Signature)
	if err != nil {
		log.Error("checkIDVerifiableCredential payload VerifyByVM failed", "err", err)
		return err
	}
	if !success {
		log.Error("checkIDVerifiableCredential payload VerifyByVM unsuccessed")
		return errors.New("checkIDVerifiableCredential payload VerifyByVM unsuccessed")
	}
	//VerifiableCredentials inner(doc) proof
	if credPayload.Header.Operation == did.Declare_Verifiable_Credential_Operation {
		if err = checkCredential(evm, credPayload.CredentialDoc.VerifiableCredential); err != nil {
			log.Error("checkIDVerifiableCredential checkCredential ", "err", err)

			return err
		}
	}
	return nil
}

func checkDIDAllMethod(evm *EVM, ownerDID string, credPayload *did.DIDPayload) (*did.Proof, error) {
	//var DIDProofArray []*id.Proof
	proof := credPayload.Proof
	if credPayload.Header.Operation == did.Revoke_Verifiable_Credential_Operation {
		verifMethod := proof.VerificationMethod
		if isIDVerifMethodMatch(evm, verifMethod, ownerDID) {
			return &proof, nil
		}
		return nil, errors.New("revoke  Proof and id is not matched")
	} else if credPayload.Header.Operation == did.Declare_Verifiable_Credential_Operation {
		if !isIDVerifMethodMatch(evm, proof.VerificationMethod, ownerDID) {
			return nil, errors.New("proof  ownerDID not match")
		}
		return &proof, nil
	} else {
		return nil, errors.New("invalid Operation")
	}
}

func isIDVerifMethodMatch(evm *EVM, verificationMethod, ID string) bool {
	return isDIDVerifMethodMatch(verificationMethod, ID) || isCustomizedVerifMethodMatch(evm, verificationMethod, ID)
}

func isDIDVerifMethodMatch(verificationMethod, ID string) bool {
	return strings.Contains(verificationMethod, ID)
}

//here issuer must be customizdDID
func isCustomizedVerifMethodMatch(evm *EVM, verificationMethod, issuer string) bool {
	prefixDid, _ := GetDIDAndUri(verificationMethod)
	//todo maybe this id is custom so tolower
	doc, err := GetIDLastDoc(evm, issuer)
	if err != nil {
		return false
	}
	Controller := doc.Controller
	//2, check is proofUriSegment public key come from controller
	if controllerArray, bControllerArray := Controller.([]interface{}); bControllerArray == true {
		//2.1 is controller exist
		for _, controller := range controllerArray {
			if controller == prefixDid {
				return true

			}
		}
	} else if controller, bController := Controller.(string); bController == true {
		if controller == prefixDid {
			return true
		}
	}
	return false
}
