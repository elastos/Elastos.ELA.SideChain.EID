package vm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/bitly/go-simplejson"
	"github.com/btcsuite/btcutil/base58"

	"github.com/elastos/Elastos.ELA.SideChain.EID/common"
	"github.com/elastos/Elastos.ELA.SideChain.EID/core/rawdb"
	"github.com/elastos/Elastos.ELA.SideChain.EID/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.EID/core/vm/did/base64url"
	"github.com/elastos/Elastos.ELA.SideChain.EID/internal/didapi"
	"github.com/elastos/Elastos.ELA.SideChain.EID/log"
	"github.com/elastos/Elastos.ELA.SideChain.EID/params"

	elacom "github.com/elastos/Elastos.ELA/common"
)

// PrecompiledContract is the basic interface for native Go contracts. The implementation
// requires a deterministic gas count based on the input size of the Run method of the
// contract.
type PrecompiledContractDID interface {
	RequiredGas(evm *EVM, input []byte) (uint64, error)     // RequiredPrice calculates the contract gas use
	Run(evm *EVM, input []byte, gas uint64) ([]byte, error) // Run runs the precompiled contract
}

var PrecompileContractsDID = map[common.Address]PrecompiledContractDID{
	common.BytesToAddress([]byte{22}):                                    &operationDID{},
	common.BytesToAddress([]byte{23}):                                    &resolveDID{},
	common.BytesToAddress(params.GetDIDVerifiableCredentialData.Bytes()): &verifyableCredential{},
}

// RunPrecompiledContract runs and evaluates the output of a precompiled contract.
func RunPrecompiledContractDID(evm *EVM, p PrecompiledContractDID, input []byte, suppliedGas uint64) (ret []byte, remainingGas uint64, err error) {
	gasCost, error := p.RequiredGas(evm, input)
	if error != nil || suppliedGas < gasCost {
		return nil, 0, error
	}
	log.Info("run did contract", "left gas", suppliedGas)
	output, err := p.Run(evm, input, suppliedGas)
	suppliedGas -= gasCost
	return output, suppliedGas, err
}

type operationDID struct{}

func checkPublicKey(publicKey *did.DIDPublicKeyInfo) error {
	if publicKey.ID == "" {
		return errors.New("check Doc PublicKey ID is empty")
	}
	if publicKey.PublicKeyBase58 == "" {
		return errors.New("check Doc PublicKey PublicKeyBase58 is empty")
	}
	return nil
}

func checkKeyReference(didWithPrefix string, authen, authorization []interface{},
	publicKey []did.DIDPublicKeyInfo) error {
	var keyExist bool
	for _, auth := range authen {
		switch auth.(type) {
		case string:
			keyString := auth.(string)
			keyExist = false
			//if it is not mine
			controller, _ := did.GetController(keyString)
			if controller != "" && controller != didWithPrefix {
				continue
			}
			for i := 0; i < len(publicKey); i++ {
				if verificationMethodEqual(publicKey[i].ID, keyString) {
					keyExist = true
					break
				}

			}
			if !keyExist {
				return errors.New("checkKeyReference authen key is not exit in public key array")
			}
		}
	}
	for _, author := range authorization {
		switch author.(type) {
		case string:
			keyString := author.(string)
			keyExist = false
			controller, _ := did.GetController(keyString)
			if controller != "" && controller != didWithPrefix {
				continue
			}
			for i := 0; i < len(publicKey); i++ {
				if verificationMethodEqual(publicKey[i].ID, keyString) {
					keyExist = true
					break
				}

			}
			if !keyExist {
				return errors.New("checkKeyReference authorization key is not exit in public key array")
			}
		}
	}
	return nil
}

// didWithPrefix did:elastos:i begin address.
func isDIDContrlMatched(controller, didWithPrefix string) bool {
	if controller != "" && controller != didWithPrefix {
		return false
	}
	return true
}

func checkAuthorization(didWithPrefix string, authorization []interface{}, publicKey []did.DIDPublicKeyInfo) error {
	for _, auth := range authorization {
		switch auth.(type) {
		case string:
			id := auth.(string)
			//id must in public key and should be other's key(controller should not didWithPrefix)
			valid := false
			//id should be other controller
			for i := 0; i < len(publicKey); i++ {
				//if this is  my public key ignore.
				if isDIDContrlMatched(publicKey[i].Controller, didWithPrefix) {
					continue
				}
				//find referenced public key
				if verificationMethodEqual(publicKey[i].ID, id) {
					valid = true
				}
			}
			//id is not valid in public or is not didWithPrefix
			if !valid {
				return errors.New("controller in authorization is not valid")
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
			if isDIDContrlMatched(didPublicKeyInfo.Controller, didWithPrefix) {
				errors.New("map[string]interface controller in authorization is not valid ")
			}
		default:
			return errors.New("[ID checkAuthorization] invalid  auth.(type)")
		}
	}
	return nil
}

// did's Authen can not be empty
// Authen at least have one default key.
func checkDIDAuthen(didWithPrefix string, authen []interface{}, publicKey []did.DIDPublicKeyInfo) error {
	//auth should not be empty
	if len(authen) == 0 {
		return errors.New("did doc Authentication is nil")
	}
	masterPubKeyVerifyOk := false
	//auth embed public must accord with checkPublicKey
	didAddress := did.GetDIDFromUri(didWithPrefix)
	for _, auth := range authen {
		switch auth.(type) {
		case string:
			id := auth.(string)
			exist := false
			for i := 0; i < len(publicKey); i++ {
				//if this is not my public key ignore.
				if !isDIDContrlMatched(publicKey[i].Controller, didWithPrefix) {
					continue
				}
				if verificationMethodEqual(publicKey[i].ID, id) {
					exist = true
					if did.IsPublickDIDMatched(publicKey[i].PublicKeyBase58, didAddress) {
						masterPubKeyVerifyOk = true
					}
				}
			}
			//id is not exist in public or is not didWithPrefix
			if !exist {
				return errors.New("controller in auth is invalid")
			}

		case map[string]interface{}:
			data, err := json.Marshal(auth)
			if err != nil {
				return errors.New("checkAuthenID Marshal auth error")
			}
			didPublicKeyInfo := new(did.DIDPublicKeyInfo)
			err = json.Unmarshal(data, didPublicKeyInfo)
			if err != nil {
				return errors.New("checkAuthenID Unmarshal DIDPublicKeyInfo error")
			}
			if err := checkPublicKey(didPublicKeyInfo); err != nil {
				return err
			}
			if !isDIDContrlMatched(didPublicKeyInfo.Controller, didWithPrefix) {
				return errors.New("Other controller can not be in authen")
			}
			for i := 0; i < len(publicKey); i++ {
				//if this is not my public key ignore.
				if !isDIDContrlMatched(publicKey[i].Controller, didWithPrefix) {
					continue
				}
				if verificationMethodEqual(publicKey[i].ID, didPublicKeyInfo.ID) {
					if did.IsPublickDIDMatched(publicKey[i].PublicKeyBase58, didAddress) {
						masterPubKeyVerifyOk = true
					}
				}
			}
		}
	}
	if !masterPubKeyVerifyOk {
		return errors.New("authen at least have one master public key")

	}
	return nil
}

// cust id  need check  authen can not have this key who's controller is not myself
func checkCustDIDAuthen(didWithPrefix string, authen []interface{}, publicKey []did.DIDPublicKeyInfo) error {
	//auth embed public must accord with checkPublicKey
	for _, auth := range authen {
		switch auth.(type) {
		case string:
			id := auth.(string)
			exist := false
			for i := 0; i < len(publicKey); i++ {
				//if this is not my public key ignore.
				if !isDIDContrlMatched(publicKey[i].Controller, didWithPrefix) {
					continue
				}
				if verificationMethodEqual(publicKey[i].ID, id) {
					exist = true
				}
			}
			//id is not exist in public or is not didWithPrefix
			if !exist {
				return errors.New("controller in auth is not valid")
			}

		case map[string]interface{}:
			data, err := json.Marshal(auth)
			if err != nil {
				return errors.New("checkAuthenID Marshal auth error")
			}
			didPublicKeyInfo := new(did.DIDPublicKeyInfo)
			err = json.Unmarshal(data, didPublicKeyInfo)
			if err != nil {
				return errors.New("checkAuthenID Unmarshal DIDPublicKeyInfo error")
			}
			if err := checkPublicKey(didPublicKeyInfo); err != nil {
				return err
			}
			if !isDIDContrlMatched(didPublicKeyInfo.Controller, didWithPrefix) {
				return errors.New("Other controller can not be in authen")
			}
		}
	}
	return nil
}

func isAuthUnique(auth []interface{}) bool {
	// New empty IDSet
	IDSet := make(map[string]bool)
	for _, auth := range auth {
		switch auth.(type) {
		case string:
			id := auth.(string)
			_, uriFregment := did.GetController(id)
			if _, ok := IDSet[uriFregment]; ok {
				return false
			}
			IDSet[uriFregment] = true
		case map[string]interface{}:
			data, err := json.Marshal(auth)
			if err != nil {
				return false
			}
			didPublicKeyInfo := new(did.DIDPublicKeyInfo)
			err = json.Unmarshal(data, didPublicKeyInfo)
			if err != nil {
				return false
			}
			//get uri fregment
			_, uriFregment := did.GetController(didPublicKeyInfo.ID)
			//
			if _, ok := IDSet[uriFregment]; ok {
				return false
			}
			IDSet[uriFregment] = true
		default:
			continue
		}
	}
	return true
}

func isPublicKeyIDUnique(p *did.DIDPayload) bool {
	// New empty IDSet
	IDSet := make(map[string]bool)
	for i := 0; i < len(p.DIDDoc.PublicKey); i++ {
		//get uri fregment
		_, uriFregment := did.GetController(p.DIDDoc.PublicKey[i].ID)
		//
		if _, ok := IDSet[uriFregment]; ok {
			return false
		}
		IDSet[uriFregment] = true
	}

	for _, auth := range p.DIDDoc.Authentication {
		switch auth.(type) {
		case map[string]interface{}:
			data, err := json.Marshal(auth)
			if err != nil {
				return false
			}
			didPublicKeyInfo := new(did.DIDPublicKeyInfo)
			err = json.Unmarshal(data, didPublicKeyInfo)
			if err != nil {
				return false
			}
			//get uri fregment
			_, uriFregment := did.GetController(didPublicKeyInfo.ID)
			//
			if _, ok := IDSet[uriFregment]; ok {
				return false
			}
			IDSet[uriFregment] = true
		default:
			continue
		}
	}
	return true
}

func isVerifiCreIDUnique(p *did.DIDPayload) bool {
	// New empty IDSet
	IDSet := make(map[string]bool)
	for _, v := range p.DIDDoc.VerifiableCredential {
		if _, ok := IDSet[v.ID]; ok {
			return false
		}
		IDSet[v.ID] = true
	}
	return true
}

func isServiceIDUnique(p *did.DIDPayload) bool {
	// New empty IDSet
	IDSet := make(map[string]bool)

	//iteraotr each sercie
	for _, service := range p.DIDDoc.Service {
		svcMap := service.(map[string]interface{})
		//iterator each item of service
		for k, v := range svcMap {
			//if it is id
			if k == did.ID_STRING {
				//id value
				id := v.(string)
				//if id is duplicate
				if _, ok := IDSet[id]; ok {
					return false
				}
				IDSet[id] = true
			}
		}
	}
	return true
}

func getController(verificationMethod string, doc *did.DIDDoc) string {
	for i := 0; i < len(doc.PublicKey); i++ {
		//get uri fregment
		if verificationMethodEqual(verificationMethod, doc.PublicKey[i].ID) {
			return doc.PublicKey[i].Controller
		}
	}

	for _, auth := range doc.Authentication {
		switch auth.(type) {
		case map[string]interface{}:
			data, err := json.Marshal(auth)
			if err != nil {
				return ""
			}
			didPublicKeyInfo := new(did.DIDPublicKeyInfo)
			err = json.Unmarshal(data, didPublicKeyInfo)
			if err != nil {
				return ""
			}
			if verificationMethodEqual(verificationMethod, didPublicKeyInfo.ID) {
				return didPublicKeyInfo.Controller
			}
		default:
			continue
		}
	}
	return ""
}

func checkPayloadSyntax(p *did.DIDPayload, evm *EVM, isDID bool) error {
	// check proof
	if p.Proof.VerificationMethod == "" {
		return errors.New("proof Creator is nil")
	}
	if p.Proof.Signature == "" {
		return errors.New("proof Created is nil")
	}
	doc := p.DIDDoc
	if p.DIDDoc != nil {
		if !isPublicKeyIDUnique(p) {
			return errors.New("doc public key id is not unique")
		}
		if !isAuthUnique(p.DIDDoc.Authentication) {
			return errors.New("doc Authentication  is not unique")
		}
		if !isAuthUnique(p.DIDDoc.Authorization) {
			return errors.New("doc Authorization is not unique")
		}
		if evm.Context.BlockNumber.Cmp(evm.chainConfig.DocArraySortHeight) > 0 {
			if !isVerifiCreIDUnique(p) {
				return errors.New("doc verifiable credential id is not unique")
			}
			if !isServiceIDUnique(p) {
				return errors.New("doc service id is not unique")
			}
		}
		if isDID {
			if err := checkDIDAuthen(p.DIDDoc.ID, p.DIDDoc.Authentication, p.DIDDoc.PublicKey); err != nil {
				return err
			}
			if err := checkAuthorization(p.DIDDoc.ID, p.DIDDoc.Authorization, p.DIDDoc.PublicKey); err != nil {
				return err
			}
		}

		if err := checkKeyReference(doc.ID, doc.Authentication, doc.Authorization, doc.PublicKey); err != nil {
			return err
		}
		if p.DIDDoc.Expires == "" {
			return errors.New("did doc Expires is nil")
		}

		for _, pkInfo := range p.DIDDoc.PublicKey {
			if err := checkPublicKey(&pkInfo); err != nil {
				return err
			}
		}
		DIDProofArray, err := getDocProof(p.DIDDoc.Proof)
		if err != nil {
			return err
		}
		for _, proof := range DIDProofArray {
			if evm.Context.BlockNumber.Cmp(evm.chainConfig.CustomizeDIDHeight) > 0 {
				if proof.Creator == "" {
					return errors.New("proof Creator is null")
				}
				if proof.Type != "ECDSAsecp256r1" {
					return errors.New("Type != ECDSAsecp256r1")
				}
			}

			if proof.Created == "" {
				return errors.New("proof Created is null")
			}
			if proof.SignatureValue == "" {
				return errors.New("proof SignatureValue is null")
			}

		}
	}
	return nil
}

// proof controller must unique ,not expired ,not deactive
// must belong to his conroller
func IsDocProofCtrUnique_Bk(proof interface{}, evm *EVM) error {
	DIDProofArray := make([]*did.DocProof, 0)
	CustomizedDIDProof := &did.DocProof{}
	//var bExist bool
	if err := Unmarshal(proof, &DIDProofArray); err == nil {
		//check unique
		creatorMgr := make(map[string]struct{}, 0)
		for _, CustomizedDIDProof := range DIDProofArray {
			prefixedDID, _ := GetDIDAndUri(CustomizedDIDProof.Creator)
			ctrlInvalid, err := isControllerInvalid(evm, prefixedDID)
			if err != nil {
				return err
			}
			if ctrlInvalid {
				return errors.New("one of the controller is ctrlInvalid")
			}
			if _, ok := creatorMgr[CustomizedDIDProof.Creator]; ok {
				return errors.New("proof creator is duplicated")
			}
			creatorMgr[CustomizedDIDProof.Creator] = struct{}{}
		}

	} else if err := Unmarshal(proof, CustomizedDIDProof); err == nil {
		prefixedDID, _ := GetDIDAndUri(CustomizedDIDProof.Creator)
		ctrlInvalid, err := isControllerInvalid(evm, prefixedDID)
		if err != nil {
			return err
		}
		if ctrlInvalid {
			return errors.New("one of the controller is ctrlInvalid")
		}
	} else {
		//error
		return errors.New("isCustomDocVerifMethodDefKey Invalid proof type")
	}

	return nil
}

// 1. proof VerificationMethod must be unique
// 2. proof controller must not deactive
// 3. proof controller must not expired
// 4. proof controller must from controller
func chckDocProofCtr(Doc *did.DIDDoc, evm *EVM) error {
	DIDProofArray := make([]*did.DocProof, 0)
	CustomizedDIDProof := &did.DocProof{}
	//check proof array VerificationMethod unique
	if err := Unmarshal(Doc.Proof, &DIDProofArray); err == nil {
		//check unique
		creatorMgr := make(map[string]struct{}, 0)
		for _, proof := range DIDProofArray {
			if _, ok := creatorMgr[proof.Creator]; ok {
				return errors.New("proof creator is duplicated")
			}
			creatorMgr[proof.Creator] = struct{}{}
		}

	} else if err := Unmarshal(Doc.Proof, CustomizedDIDProof); err == nil {
		DIDProofArray = append(DIDProofArray, CustomizedDIDProof)
	} else {
		//error
		return errors.New("isCustomDocVerifMethodDefKey Invalid proof type")
	}

	//check every controller is not deactive or expired
	for _, proof := range DIDProofArray {
		//controller is  customizedid's controller
		controller, _ := GetDIDAndUri(proof.Creator)

		if !HaveCtrl(Doc.Controller, controller) {
			return errors.New("doc not have this controller")
		}
		// controller must  valid
		ctrlInvalid, err := isControllerInvalid(evm, controller)
		if err != nil {
			return err
		}
		if ctrlInvalid {
			return errors.New("one of the controller is ctrlInvalid")
		}
	}

	return nil
}

// 1. proof VerificationMethod must be unique
// 2. proof controller must not deactive
// 3. proof controller must not expired
// 4. proof controller must from controller
func IsTicketProofCtrInvalid(proof interface{}, evm *EVM, ID string) error {
	verifyDoc, err := getVerifyDocMultisign(evm, ID)
	if err != nil {
		return err
	}
	ticketProofArray := make([]*did.TicketProof, 0)
	ticketProof := &did.TicketProof{}
	//check proof array VerificationMethod unique
	if err := Unmarshal(proof, &ticketProofArray); err == nil {
		//check unique
		creatorMgr := make(map[string]struct{}, 0)
		for _, proof := range ticketProofArray {
			if _, ok := creatorMgr[proof.VerificationMethod]; ok {
				return errors.New("proof creator is duplicated")
			}
			creatorMgr[proof.VerificationMethod] = struct{}{}
		}

	} else if err := Unmarshal(proof, ticketProof); err == nil {
		ticketProofArray = append(ticketProofArray, ticketProof)
	} else {
		//error
		return errors.New("isCustomDocVerifMethodDefKey Invalid proof type")
	}

	//

	//check every controller is not deactive or expired
	for _, proof := range ticketProofArray {
		//controller is  customizedid's controller
		controller, _ := GetDIDAndUri(proof.VerificationMethod)

		if !HaveCtrl(verifyDoc.Controller, controller) {
			return errors.New("doc not have this controller")
		}
		// controller must  valid
		ctrlInvalid, err := isControllerInvalid(evm, controller)
		if err != nil {
			return err
		}
		if ctrlInvalid {
			return errors.New("one of the controller is ctrlInvalid")
		}
	}

	return nil
}

/*
0. controller must unique
1. controller must have did:elastos:  prefix
2. controller must did in chain
3. controller must valid
*/
func IsControllerInvalid(controller interface{}, evm *EVM) error {
	if contrMgr, err := checkControllerUnique(controller, evm); err != nil {
		return err
	} else {
		// every controller must have did:elastos:  prefix and must did in chain
		for contrl := range contrMgr {
			if !strings.HasPrefix(contrl, did.DID_ELASTOS_PREFIX) {
				return errors.New("contrl must have prefix did:elastos:")
			}
			isDID, err := evm.StateDB.IsDID(contrl)
			//all contrller must be did and alreday in the block chain
			if err != nil || isDID == false {
				return errors.New("not all the controler is already in the chain")
			}
			ctrlInvalid, err := isControllerInvalid(evm, contrl)
			if err != nil {
				return err
			}
			if ctrlInvalid {
				return errors.New("one of the controller is  Invalid")
			}
		}
		return nil
	}
}

// if controller is unique return  controllers and nil
// else return nil and error
func checkControllerUnique(controller interface{}, evm *EVM) (map[string]struct{}, error) {
	//if is controller array
	contrMgr := make(map[string]struct{}, 0)
	if controllerArray, ok := controller.([]interface{}); ok {
		if len(controllerArray) == 1 {
			return nil, errors.New("controller array must have more than one controller")
		}
		for _, controller := range controllerArray {
			if contrl, ok := controller.(string); !ok {
				return nil, errors.New("checkControllerUnique controller is not string")
			} else {
				if _, ok := contrMgr[contrl]; ok {
					return nil, errors.New("controller is duplicated")
				}
				contrMgr[contrl] = struct{}{}
			}
		}
	} else {
		if contrl, ok := controller.(string); !ok {
			return nil, errors.New("checkControllerUnique controller is not string")
		} else {
			contrMgr[contrl] = struct{}{}
		}
	}
	return contrMgr, nil
}

func getCtrlLen(ctrl interface{}) int {
	if ctrlArray, ok := ctrl.([]interface{}); ok {
		return len(ctrlArray)
	} else {
		return 1
	}
}

func getDocProofLen(proof interface{}) int {
	DIDProofArray := make([]*did.DocProof, 0)
	CustomizedDIDProof := &did.DocProof{}
	//var bExist bool
	if err := Unmarshal(proof, &DIDProofArray); err == nil {
		return len(DIDProofArray)

	} else if err := Unmarshal(proof, CustomizedDIDProof); err == nil {
		return 1
		//if one controller no need check
	} else {
		//error
		return 0
	}
}

func isCtrlLenEqual(newCtrl, oldCtrl interface{}) bool {
	newLen := getCtrlLen(newCtrl)
	oldLen := getCtrlLen(oldCtrl)
	return newLen == oldLen
}

func isCtrlEqual(newCtrl, oldCtrl interface{}) bool {
	//before compare we need some sort
	sortControllerSlice(newCtrl)
	sortControllerSlice(oldCtrl)
	var newCtrlArray, oldCtrlArray []interface{}
	var ok bool
	if newCtrlArray, ok = newCtrl.([]interface{}); ok {
		if oldCtrlArray, ok = oldCtrl.([]interface{}); !ok {
			return false
		}
		if len(newCtrlArray) != len(oldCtrlArray) {
			return false
		}
		for i, controller := range newCtrlArray {
			if controller != oldCtrlArray[i] {
				return false
			}
		}
		return true

	} else {
		return newCtrl == oldCtrl
	}
}

func HaveCtrl(docCtrl interface{}, controller string) bool {
	var newCtrlArray []interface{}
	var ok bool
	if newCtrlArray, ok = docCtrl.([]interface{}); ok {
		for _, ctrl := range newCtrlArray {
			if ctrl == controller {
				return true
			}
		}
		return false

	} else {
		return docCtrl == controller
	}
}

/*
1. if controller len >1 MultiSig != ""
2. if controller len =1 multsig == “”
*/
func checkMultSignController(p *did.DIDPayload, evm *EVM) error {
	if p == nil || p.DIDDoc == nil {
		return errors.New("checkMultSignController p == nil || p.DIDDoc==nil")
	}
	ctrlLen := getCtrlLen(p.DIDDoc.Controller)
	if ctrlLen > 1 && p.DIDDoc.MultiSig == "" {
		return errors.New("ctrlLen > 1 && p.DIDDoc.MultiSig is empty")
	}
	if ctrlLen == 1 && p.DIDDoc.MultiSig != "" {
		return errors.New("ctrlLen == 1 && p.DIDDoc.MultiSig is not empty")
	}

	if p.DIDDoc.MultiSig != "" {
		M, N, err := GetMultisignMN(p.DIDDoc.MultiSig)
		if err != nil {
			return err
		}
		if M > N {
			return errors.New("checkMultSignController M > N")
		}
		if N <= 1 {
			return errors.New("N <= 1")
		}
		if M <= 0 {
			return errors.New("M <=0")
		}
		if N != getCtrlLen(p.DIDDoc.Controller) {
			return errors.New("checkMultSignController N != getCtrlLen(p.DIDDoc.Controller")
		}
		if p.Header.Operation == did.Update_DID_Operation {
			verifyDoc, err := getVerifyDocMultisign(evm, p.DIDDoc.ID)
			if err != nil {
				return err
			}
			if !isCtrlEqual(p.DIDDoc.Controller, verifyDoc.Controller) {
				return errors.New("Ctrl not Equal")
			}
			if p.DIDDoc.MultiSig != verifyDoc.MultiSig {
				return errors.New("update can not change MultiSig")
			}
		}
	} else {
		proofLen := getDocProofLen(p.DIDDoc.Proof)
		if proofLen > 1 {
			return errors.New("MultiSig should not empty when doc is multsign")
		}
	}
	return nil
}

func isPayloadCtrlInvalid(VerificationMethod string, evm *EVM) error {
	prefixedDID, _ := GetDIDAndUri(VerificationMethod)
	ctrlInvalid, err := isControllerInvalid(evm, prefixedDID)
	if err != nil {
		return err
	}
	if ctrlInvalid {
		return errors.New(" isPayloadCtrlInvalid VerificationMethod is ctrlInvalid")
	}
	return nil
}

// customized did public key cotroller should be itself
func checkCustomPublicKeyController(didWithPrefix string, publicKey []did.DIDPublicKeyInfo) error {
	for i := 0; i < len(publicKey); i++ {
		//get uri fregment
		if publicKey[i].Controller != "" && publicKey[i].Controller != didWithPrefix {
			return errors.New("customizedid public key all controller must itself")
		}
	}
	return nil
}

func checkCustomIDPayloadSyntax(p *did.DIDPayload, evm *EVM) error {
	if p == nil || evm == nil {
		return errors.New("checkCustomIDPayloadSyntax p == nil || evm ==nil")
	}
	//check cutomized uniqued property
	if p.DIDDoc != nil {
		log.Debug("checkCustomIDPayloadSyntax", "ID", p.DIDDoc.ID)

		if err := checkCustomPublicKeyController(p.DIDDoc.ID, p.DIDDoc.PublicKey); err != nil {
			return err
		}
		//
		if err := checkCustDIDAuthen(p.DIDDoc.ID, p.DIDDoc.Authentication, p.DIDDoc.PublicKey); err != nil {
			return err
		}
		if err := IsControllerInvalid(p.DIDDoc.Controller, evm); err != nil {
			return err
		}
		if err := checkMultSignController(p, evm); err != nil {
			return err
		}
		if err := chckDocProofCtr(p.DIDDoc, evm); err != nil {
			return err
		}
		if len(p.DIDDoc.Authorization) != 0 {
			return errors.New("customized did can not have Authorization")
		}

		if p.Header.Operation == did.Transfer_DID_Operation {
			//customized deactive or expires
			if err := isCustomizedidInvalid(evm, p.DIDDoc.ID); err != nil {
				return err
			}
			//check ticket proof controller deactive or expires
			if err := IsTicketProofCtrInvalid(p.Ticket.Proof, evm, p.DIDDoc.ID); err != nil {
				return err
			}

		}
	}
	return checkPayloadSyntax(p, evm, false)
}

func (j *operationDID) RequiredGas(evm *EVM, input []byte) (uint64, error) {
	data := getData(input, 32, uint64(len(input))-32)
	p := new(did.DIDPayload)
	if err := json.Unmarshal(data, p); err != nil {
		return params.DIDBaseGasCost, err
	}

	switch p.Header.Operation {
	case did.Create_DID_Operation, did.Update_DID_Operation:
		payloadBase64, _ := base64url.DecodeString(p.Payload)
		payloadInfo := new(did.DIDDoc)
		if err := json.Unmarshal(payloadBase64, payloadInfo); err != nil {
			return params.DIDBaseGasCost, err
		}
		p.DIDDoc = payloadInfo

		isDID := isRegistDID(p.DIDDoc)

		configHeight := evm.chainConfig.OldDIDMigrateHeight
		configAddr := evm.chainConfig.OldDIDMigrateAddr
		senderAddr := evm.Context.Origin.String()
		if configHeight == nil ||
			evm.Context.BlockNumber.Cmp(configHeight) > 0 ||
			senderAddr != configAddr ||
			!isDID {

			buf := new(bytes.Buffer)
			p.Serialize(buf, did.DIDVersion)
			//if it is normal did  lenth is 0
			ID := payloadInfo.ID
			if isDID {
				ID = ""
			}
			needFee := getIDTxFee(evm, ID, payloadInfo.Expires, p.Header.Operation, payloadInfo.Controller, buf.Len())

			log.Info("#### did RequiredGas getIDTxFee ", "needFee", uint64(needFee))
			return uint64(needFee), nil
		}
	}
	return params.DIDBaseGasCost, nil
}

func checkExpires(Expires string, blockTimeStamp *big.Int) error {
	expiresTime, err := time.Parse(time.RFC3339, Expires)
	if err != nil {
		return errors.New("invalid Expires format")
	}
	fmt.Println("expiresTime.Unix()", expiresTime.Unix())
	fmt.Println("blockTimeStamp.Int64()", blockTimeStamp.Int64())

	//expiresTime
	if expiresTime.Unix() <= blockTimeStamp.Int64() {
		return errors.New("Expires time is too short")
	}
	return nil
}

func (j *operationDID) Run(evm *EVM, input []byte, gas uint64) ([]byte, error) {
	//block height from context BlockNumber. config height address from config

	configHeight := evm.chainConfig.OldDIDMigrateHeight
	configAddr := evm.chainConfig.OldDIDMigrateAddr
	senderAddr := evm.Context.Origin.String()
	log.Info("####", "configAddr", configAddr, "senderAddr", senderAddr)

	//BlockNumber <= configHei
	//ght senderAddr must be configAddr
	if evm.Context.BlockNumber.Cmp(configHeight) <= 0 {
		if senderAddr != configAddr {
			log.Info("#### BlockNumber.Cmp(configHeight) <= 0 or callerAddress.String() != configAddr")
			return false32Byte, errors.New("Befor configHeight only configAddr can send DID tx")
		}
	} else {
		if senderAddr == configAddr {
			log.Info("#### BlockNumber.Cmp(configHeight) > 0 callerAddress.String() should not configAddr")
			return false32Byte, errors.New("after configHeight  configAddr can not send migrate DID tx")
		}
	}

	data := getData(input, 32, uint64(len(input))-32)
	p := new(did.DIDPayload)
	if err := json.Unmarshal(data, p); err != nil {
		log.Error("DIDPayload input is error", "input", string(data))
		return false32Byte, err
	}
	switch p.Header.Operation {
	case did.Create_DID_Operation, did.Update_DID_Operation:
		payloadBase64, _ := base64url.DecodeString(p.Payload)
		payloadInfo := new(did.DIDDoc)
		if err := json.Unmarshal(payloadBase64, payloadInfo); err != nil {
			return false32Byte, errors.New("createDIDVerify Payload is error")
		}
		p.DIDDoc = payloadInfo

		if !strings.HasPrefix(p.DIDDoc.ID, did.DID_ELASTOS_PREFIX) {
			return false32Byte, errors.New("ID must have prefix did:elastos:")
		}
		var err error
		isDID := isRegistDID(p.DIDDoc)
		if isDID {
			if err = checkRegisterDID(evm, p, gas); err != nil {
				log.Error("checkRegisterDID error", "error", err, "ID", p.DIDDoc.ID)
			}
		} else {
			if err = checkCustomizedDID(evm, p, gas); err != nil {
				log.Error("checkCustomizedDID error", "error", err, "ID", p.DIDDoc.ID)
			}
		}
		if err != nil {
			return false32Byte, err
		}
		buf := new(bytes.Buffer)
		p.Serialize(buf, did.DIDVersion)
		evm.StateDB.AddDIDLog(p.DIDDoc.ID, p.Header.Operation, buf.Bytes())
	case did.Transfer_DID_Operation:
		payloadBase64, _ := base64url.DecodeString(p.Payload)
		payloadInfo := new(did.DIDDoc)
		if err := json.Unmarshal(payloadBase64, payloadInfo); err != nil {
			return false32Byte, errors.New("createDIDVerify Payload is error")
		}
		p.DIDDoc = payloadInfo
		ticketBase64data, _ := base64url.DecodeString(p.Header.Ticket)
		ticket := new(did.CustomIDTicket)
		if err := json.Unmarshal(ticketBase64data, ticket); err != nil {
			return false32Byte, errors.New("transfer ticket to CustomIDTicket is error")
		}
		p.DIDDoc = payloadInfo
		p.Ticket = ticket
		if err := checkCustomizedDID(evm, p, gas); err != nil {
			log.Error("checkCustomizedDID error", "error", err)
			return false32Byte, err
		}
		buf := new(bytes.Buffer)
		p.Serialize(buf, did.DIDVersion)
		evm.StateDB.AddDIDLog(p.DIDDoc.ID, p.Header.Operation, buf.Bytes())
	case did.Deactivate_DID_Operation:
		if err := checkDeactivateDID(evm, p); err != nil {
			log.Error("checkDeactivateDID error", "error", err)
			return false32Byte, err
		}
		id := p.Payload
		buf := new(bytes.Buffer)
		p.Serialize(buf, did.DIDVersion)
		evm.StateDB.AddDIDLog(id, p.Header.Operation, buf.Bytes())
	case did.Declare_Verifiable_Credential_Operation:
		payloadBase64, _ := base64url.DecodeString(p.Payload)
		credentialDoc := new(did.VerifiableCredentialDoc)
		if err := json.Unmarshal(payloadBase64, credentialDoc); err != nil {
			return false32Byte, errors.New("createDIDVerify Payload is error")
		}
		p.CredentialDoc = credentialDoc
		if err := checkCredentialTX(evm, p); err != nil {
			log.Error("checkCredentialTX error", "error", err)
			return false32Byte, err
		}
		buf := new(bytes.Buffer)
		p.Serialize(buf, did.DIDVersion)
		evm.StateDB.AddDIDLog(p.CredentialDoc.ID, p.Header.Operation, buf.Bytes())
	case did.Revoke_Verifiable_Credential_Operation:
		if err := checkCredentialTX(evm, p); err != nil {
			log.Error("checkCredentialTX error", "error", err)
			return false32Byte, err
		}
		buf := new(bytes.Buffer)
		p.Serialize(buf, did.DIDVersion)
		creDentialID := p.Payload
		evm.StateDB.AddDIDLog(creDentialID, p.Header.Operation, buf.Bytes())
	default:
		log.Error("error operation", "operation", p.Header.Operation)
		return false32Byte, errors.New("error operation:" + p.Header.Operation)
	}
	return true32Byte, nil
}

func isRegistDID(didDoc *did.DIDDoc) bool {
	idString := did.GetDIDFromUri(didDoc.ID)

	for _, pkInfo := range didDoc.PublicKey {
		if pkInfo.Controller != "" && pkInfo.Controller != didDoc.ID {
			continue
		}
		publicKey := base58.Decode(pkInfo.PublicKeyBase58)
		if did.IsMatched(publicKey, idString) {
			return true
		}
	}
	return false
}

type resolveDID struct{}

func (j *resolveDID) RequiredGas(evm *EVM, input []byte) (uint64, error) {
	return params.ResolveDIDCost, nil
}

func (j *resolveDID) Run(evm *EVM, input []byte, gas uint64) ([]byte, error) {
	var didDocState didapi.DidDocState = didapi.NonExist
	data := getData(input, 32, uint64(len(input)-32))
	params := make(map[string]interface{})

	err := json.Unmarshal(data, &params)
	if err != nil {
		return false32Byte, errors.New("resolveDID input is error" + string(data))
	}

	//remove DID_ELASTOS_PREFIX
	idParam, ok := params["did"].(string)
	if !ok {
		return false32Byte, errors.New("did is null")
	}
	id := idParam
	if rawdb.IsURIHasPrefix(idParam) {
		id = did.GetDIDFromUri(id)
	}

	//check is valid address
	_, err = elacom.Uint168FromAddress(id)
	if err != nil {
		return false32Byte, errors.New("invalid did")
	}

	isGetAll, ok := params["all"].(bool)
	if !ok {
		isGetAll = false
	}

	branchPath, ok := params["branch"].([]interface{})
	if !ok {
		return false32Byte, errors.New("branch is null")
	}

	var rpcPayloadDid didapi.ResolvePayloadDIDInfo
	buf := new(bytes.Buffer)
	buf.WriteString(idParam)
	txData, err := evm.StateDB.GetLastDIDTxData(buf.Bytes(), evm.chainConfig)
	if err != nil {
		return false32Byte, errors.New("did is not exist")
	}

	var txsData []did.DIDTransactionData
	if isGetAll {
		txsData, err = evm.StateDB.GetAllDIDTxData(buf.Bytes(), evm.chainConfig)
		if err != nil {
			return false32Byte, errors.New("get did transaction failed")
		}
	} else {
		if txData != nil {
			txsData = append(txsData, *txData)
		}
	}

	for index, txData := range txsData {
		rpcPayloadDid.DID = txData.Operation.DIDDoc.ID
		err, timestamp := getTxTime(evm, txData.TXID)
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
			//todo IsIDDeactivated should be IsIDDeactivated
			if evm.StateDB.IsIDDeactivated(idParam) {
				didDocState = didapi.Deactivated
				deactiveTXData, err := getDeactiveTx(evm, buf.Bytes())
				if err != nil {
					return nil, err
				}
				rpcPayloadDid.RpcTXDatas = append(rpcPayloadDid.RpcTXDatas, deactiveTXData.ToResolveTxData())
			} else {
				didDocState = didapi.Valid
			}
			rpcPayloadDid.Status = int(didDocState)
		}
		rpcPayloadDid.RpcTXDatas = append(rpcPayloadDid.RpcTXDatas, tempTXData.ToResolveTxData())
	}

	res, err := json.Marshal(rpcPayloadDid)
	if err != nil {
		return false32Byte, err
	}
	jin, err := simplejson.NewJson(res)
	if err != nil {
		log.Error("set simple json error", "error", err)
		return false32Byte, err
	}

	for _, p := range branchPath {
		if path, ok := p.(string); ok {
			jin = jin.Get(path)
		} else if path, ok := p.(float64); ok {
			jin = jin.GetIndex(int(path))
		}
	}
	inter := jin.Interface()
	if jin == nil {
		return false32Byte, errors.New("get value error")
	}
	vv, err := json.Marshal(inter)
	log.Info("resolve did", "return", string(vv), "err", err)
	return vv, err
}

func getTxTime(evm *EVM, txid string) (error, uint64) {
	hash := common.HexToHash(txid)
	tx, blockHash, blockNumber, _ := evm.StateDB.ReadTransaction(hash)
	if tx == nil {
		return errors.New("unkown tx"), 0
	}
	block := evm.StateDB.ReadBlock(blockHash, blockNumber)
	if block == nil {
		return errors.New("unkown block header"), 0

	}
	return nil, block.Time()
}

func getDeactiveTx(evm *EVM, idKey []byte) (*didapi.RpcTranasactionData, error) {
	deactiveTxData, err := evm.StateDB.GetDeactivatedTxData(idKey, evm.chainConfig)
	if err != nil {
		return nil, errors.New("get did deactivate transaction failed")
	}
	//change from DIDTransactionData to RpcTranasactionData
	rpcTXData := new(didapi.RpcTranasactionData)
	succe := rpcTXData.FromTranasactionData(*deactiveTxData)
	if succe == false {
		return nil, errors.New("change deactive tx data failed")
	}
	//fill tx Timestamp
	err, timestamp := getTxTime(evm, rpcTXData.TXID)
	if err != nil {
		return nil, errors.New("get did deactivate transaction failed" + err.Error())
	}
	rpcTXData.Timestamp = time.Unix(int64(timestamp), 0).UTC().Format(time.RFC3339)
	return rpcTXData, nil
}

type verifyableCredential struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (v *verifyableCredential) RequiredGas(evm *EVM, input []byte) (uint64, error) {
	return params.ResolveDIDCost, nil
}

func (v *verifyableCredential) Run(evm *EVM, input []byte, gas uint64) ([]byte, error) {
	data := getData(input, 32, uint64(len(input)-32))
	idParam := string(data)
	fmt.Println("verifyableCredential >>>>>> idParam", idParam)
	bytesData := new(bytes.Buffer)
	credentialIDWithPrefix := idParam
	if !rawdb.IsURIHasPrefix(credentialIDWithPrefix) {
		//add prefix
		credentialIDWithPrefix = did.DID_ELASTOS_PREFIX + idParam
	}

	fmt.Println("verifyableCredential credentialID ", credentialIDWithPrefix)
	buf := new(bytes.Buffer)
	buf.WriteString(credentialIDWithPrefix)
	// credentialID can be customized

	didTxData, err := evm.StateDB.GetLastDIDTxData(buf.Bytes(), evm.ChainConfig())
	if err != nil {
		fmt.Println("GetLastDIDTxData err ", err)
		return bytesData.Bytes(), err
	}
	credentials := didTxData.Operation.DIDDoc.VerifiableCredential
	count := len(credentials)
	if count <= 0 {
		return bytesData.Bytes(), nil
	}

	bytesData.WriteRune('[')
	for i, vc := range credentials {
		if err = did.MarshalVerifiableCredentialData(vc.VerifiableCredentialData, bytesData); err != nil {
			return nil, err
		}
		if i != count-1 {
			bytesData.WriteRune(',')
		}
	}
	bytesData.WriteRune(']')
	fmt.Println("return >>>>> ", bytesData.String())
	return bytesData.Bytes(), nil
}

func (v *verifyableCredential) isDID(evm *EVM, idParam string) (bool, error) {
	idWithPrefix := idParam
	if !rawdb.IsURIHasPrefix(idWithPrefix) {
		//add prefix
		idWithPrefix = did.DID_ELASTOS_PREFIX + idParam
	}
	buf := new(bytes.Buffer)
	buf.WriteString(idWithPrefix)
	_, err := evm.StateDB.GetLastDIDTxData(buf.Bytes(), evm.ChainConfig())
	if err != nil {
		idWithPrefix = strings.ToLower(idWithPrefix)
		buf.Reset()
		buf.WriteString(idWithPrefix)
		//try customized id
		_, err := evm.StateDB.GetLastDIDTxData(buf.Bytes(), evm.ChainConfig())
		if err != nil {
			//if we can not find customized then it means non exist
			return false, err
		}
		return false, nil
	}
	return true, nil
}
