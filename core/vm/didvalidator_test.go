package vm

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/assert"

	"github.com/elastos/Elastos.ELA.SideChain.EID/common"
	"github.com/elastos/Elastos.ELA.SideChain.EID/common/math"
	"github.com/elastos/Elastos.ELA.SideChain.EID/core/rawdb"
	"github.com/elastos/Elastos.ELA.SideChain.EID/core/state"
	"github.com/elastos/Elastos.ELA.SideChain.EID/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.EID/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.EID/core/vm/did/base64url"
	"github.com/elastos/Elastos.ELA.SideChain.EID/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.EID/ethdb"
	"github.com/elastos/Elastos.ELA.SideChain.EID/params"

	types2 "github.com/elastos/Elastos.ELA.SideChain/types"
	elacom "github.com/elastos/Elastos.ELA/common"
	elaCrypto "github.com/elastos/Elastos.ELA/crypto"
)

var didPayloadBytesMashal = []byte(
	`{
        "id" : "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN",
		"controller" : [ "did:elastos:iXcRhYB38gMt1phi5JXJMjeXL2TL8cg58y", "did:elastos:igHbSCez6H3gTuVPzwNZRrdj92GCJ6hD5d" ],
		"verifiableCredential" : [ {
			"id" : "did:elastos:example#profile",
			"type" : [ "BasicProfileCredential", "SelfProclaimedCredential" ],
			"issuer" : "did:elastos:example",
			"issuanceDate" : "2021-01-28T06:38:35Z",
			"expirationDate" : "2026-01-28T06:38:35Z",
			"credentialSubject" : {
				"id" : "did:elastos:example",
				"name" : "Example LLC",
				"email" : "contact@example.com",
				"website" : "https://example.com/"
			},
			"proof" : {
				"type" : "ECDSAsecp256r1",
				"created" : "2021-01-28T06:38:35Z",
				"verificationMethod" : "did:elastos:imUUPBfrZ1yZx6nWXe6LNN59VeX2E6PPKj#primary",
				"signature" : "e-W2o8Grqd0IrkWOEvGjHvWmTKl_hwuQFwk3rR1YZmxBySO7nYoardIZ5PLT_6rSViXNd8jPVFKXQRVbpeBVhQ"
			}
		} ],
        "publicKey":[{ "id": "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default",
                       "type":"ECDSAsecp256r1",
                       "controller":"did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN",
                       "publicKeyBase58":"27bqfhMew6TjL4NMz2u8b2cFCvGovaELqr19Xytt1rDmd"
                      }
                    ],
        "authentication":["did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default",
                          {
                               "id": "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default",
                               "type":"ECDSAsecp256r1",
                               "controller":"did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN",
                               "publicKeyBase58":"zNxoZaZLdackZQNMas7sCkPRHZsJ3BtdjEvM2y5gNvKJ"
                           }
                         ],
        "authorization":["did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default"],
		"service": [
			{
			  "id": "testid1",
              "type": "testtype1",
              "serviceEndpoint": "testendpoint1"
		   },
			{
			  "id": "testid2",
              "serviceEndpoint": "testendpoint2",
              "type": "testtype2",
              "abc": "123",
              "cde": "789",
              "bcd": "456"
		   }
		],
        "expires" : "2023-02-10T17:00:00Z"
	}`)

var sortedDIDPayloadData2 = `{"id":"did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN","controller":["did:elastos:iXcRhYB38gMt1phi5JXJMjeXL2TL8cg58y","did:elastos:igHbSCez6H3gTuVPzwNZRrdj92GCJ6hD5d"],"publicKey":[{"id":"did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default","type":"ECDSAsecp256r1","controller":"did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN","publicKeyBase58":"27bqfhMew6TjL4NMz2u8b2cFCvGovaELqr19Xytt1rDmd"}],"authentication":["did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default",{"id":"did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default","type":"ECDSAsecp256r1","controller":"did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN","publicKeyBase58":"zNxoZaZLdackZQNMas7sCkPRHZsJ3BtdjEvM2y5gNvKJ"}],"authorization":["did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default"],"verifiableCredential":[{"id":"did:elastos:example#profile","type":["BasicProfileCredential","SelfProclaimedCredential"],"issuer":"did:elastos:example","issuanceDate":"2021-01-28T06:38:35Z","expirationDate":"2026-01-28T06:38:35Z","credentialSubject":{"id":"did:elastos:example","email":"contact@example.com","name":"Example LLC","website":"https://example.com/"},"proof":{"type":"ECDSAsecp256r1","created":"2021-01-28T06:38:35Z","verificationMethod":"did:elastos:imUUPBfrZ1yZx6nWXe6LNN59VeX2E6PPKj#primary","signature":"e-W2o8Grqd0IrkWOEvGjHvWmTKl_hwuQFwk3rR1YZmxBySO7nYoardIZ5PLT_6rSViXNd8jPVFKXQRVbpeBVhQ"}}],"service":[{"id":"testid1","type":"testtype1","serviceEndpoint":"testendpoint1"},{"id":"testid2","type":"testtype2","serviceEndpoint":"testendpoint2","abc":"123","bcd":"456","cde":"789"}],"expires":"2023-02-10T17:00:00Z"}`

func TestMashalDIDPayloadData(t *testing.T) {
	// test for unmarshal did payload from bytes
	info := new(did.DIDPayloadData)
	err := json.Unmarshal(didPayloadBytesMashal, info)
	assert.NoError(t, err)

	data, err := did.MarshalDIDPayloadData(info)
	assert.NoError(t, err)

	buf := new(bytes.Buffer)
	buf.WriteString(sortedDIDPayloadData2)
	assert.Equal(t, buf.Bytes(), data)
	assert.Equal(t, info.GetData(), data)
}

var (
	bankKey, _ = crypto.GenerateKey()
	bankAddr   = crypto.PubkeyToAddress(bankKey.PublicKey)

	userKey1, _ = crypto.GenerateKey()
	userAddr1   = crypto.PubkeyToAddress(userKey1.PublicKey)

	id1DocByts                      []byte
	id2DocByts                      []byte
	id11DocByts                     []byte
	idUser1DocByts                  []byte
	idUser2DocByts                  []byte
	customizedDIDDocSingleContrller []byte
	customizedDIDDocBytes2          []byte

	headerPayloadBytes       []byte
	changeDocPayload         []byte
	declareCredDocPayload    []byte
	issuerDocByts            []byte
	docDocBytes              []byte
	specialCharacterDocBytes []byte

	didDocPubKeyTest       []byte
	jianbinCtrl1PubKeyTest []byte
	jianbinCtrl2PubKeyTest []byte
	jianbinCtrl3PubKeyTest []byte
	jianbinCtrl4PubKeyTest []byte
	jianbinCtrl5PubKeyTest []byte

	custmizeDIDSingleCtrlTest  []byte
	custmizeDIDMultyCtrlTest   []byte
	custmizeDIDMultyCtrlTestJB []byte

	custIDSingleSignDocBytes1 []byte
	custIDVerifCredDocBytes   []byte
	didVerifCred              []byte
	user1IDDocByts            []byte
	user2IDDocByts            []byte
	user3IDDocByts            []byte
	user4IDDocByts            []byte
	fooIDDocBytes             []byte
	fooBarIDDocBytes          []byte
	fooBarNewIDDocBytes       []byte
	fooBarTTIDDocBytes        []byte
	custIDVerifyCredContrl    []byte

	batTTDocByts    []byte
	barzIDDocByts   []byte
	bazNewIDDocByts []byte

	//doc slice sort
	check2DocByte []byte

	//veriable credential test
	Lindalittlefish20DocByte []byte
	Lindaprofile07DocByte    []byte
)

const (
	PayloadPrivateKey     = "a38aa1f5f693a13ef0cf2f1c1c0155cbcdd9386f37b0000739f8cb50af601b7b"
	User2PrivateKeyBase58 = "AqBB8Uur4QwwBtFPeA2Yd5yF2Ni45gyz2osfFcMcuP7J"
	User2PublicKeyBase58  = "kTYQhMtoimm9wV3vy4q9EVy4Z1WxRqxhvngztdGo1Dmc"
)

func init() {
	id11DocByts, _ = LoadJsonData("./testdata/issuer.id.json")

	user1IDDocByts, _ = LoadJsonData("./testdata/user1.id.json")
	user2IDDocByts, _ = LoadJsonData("./testdata/user2.id.json")
	user3IDDocByts, _ = LoadJsonData("./testdata/user3.id.json")
	user4IDDocByts, _ = LoadJsonData("./testdata/user4.id.json")

	customizedDIDDocSingleContrller, _ = LoadJsonData("./testdata/examplecorp.id.json")
	custIDSingleSignDocBytes1, _ = LoadJsonData("./testdata/customized_did_single_sign.json")
	customizedDIDDocBytes2, _ = LoadJsonData("./testdata/foo.id.json")
	custIDVerifCredDocBytes, _ = LoadJsonData("./testdata/customized_did_verifiable_credential.json")

	headerPayloadBytes, _ = LoadJsonData("./testdata/customized_did_multi_controllers.json")
	changeDocPayload, _ = LoadJsonData("./testdata/changedocpayload.json")
	declareCredDocPayload, _ = LoadJsonData("./testdata/declareCreddocpayload.json")

	issuerDocByts, _ = LoadJsonData("./testdata/issuer.json")
	docDocBytes, _ = LoadJsonData("./testdata/document.json")
	specialCharacterDocBytes, _ = LoadJsonData("./testdata/special_character.json")

	didDocPubKeyTest, _ = LoadJsonData("./testdata/diddocpubkeytest.json")
	jianbinCtrl1PubKeyTest, _ = LoadJsonData("./testdata/jianbinctrl1.json")
	jianbinCtrl2PubKeyTest, _ = LoadJsonData("./testdata/jianbinctrl2.json")
	jianbinCtrl3PubKeyTest, _ = LoadJsonData("./testdata/jianbinctrl3.json")
	jianbinCtrl4PubKeyTest, _ = LoadJsonData("./testdata/jianbinctrl4.json")
	jianbinCtrl5PubKeyTest, _ = LoadJsonData("./testdata/jianbinctrl5.json")

	custmizeDIDSingleCtrlTest, _ = LoadJsonData("./testdata/custmizedidsinglectrltest.json")
	custmizeDIDMultyCtrlTest, _ = LoadJsonData("./testdata/custdidmultyctrltest.json")
	custmizeDIDMultyCtrlTestJB, _ = LoadJsonData("./testdata/Lindalittlefish07.json")

	didVerifCred, _ = LoadJsonData("./testdata/did_verifiable_credential.json")
	fooIDDocBytes, _ = LoadJsonData("./testdata/foo.id.json")
	fooBarIDDocBytes, _ = LoadJsonData("./testdata/foobar.id.json")
	fooBarNewIDDocBytes, _ = LoadJsonData("./testdata/foobar.new.id.json")
	fooBarTTIDDocBytes, _ = LoadJsonData("./testdata/foobar.tt.json")
	custIDVerifyCredContrl, _ = LoadJsonData("./testdata/customized_did_verifiable_credential_controllers.json")

	batTTDocByts, _ = LoadJsonData("./testdata/baz.tt.json")
	barzIDDocByts, _ = LoadJsonData("./testdata/baz.id.json")
	bazNewIDDocByts, _ = LoadJsonData("./testdata/baz.new.id.json")
	check2DocByte, _ = LoadJsonData("./testdata/check2.json")

	Lindalittlefish20DocByte, _ = LoadJsonData("./testdata/Lindalittlefish20.json")
	Lindaprofile07DocByte, _ = LoadJsonData("./testdata/Lindaprofile07.json")

}

var didPayloadBytes = []byte(
	`{
        "id" : "did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j",
        "publicKey":[{ "id": "did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j#default",
                       "type":"ECDSAsecp256r1",
                       "controller":"did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j",
                       "publicKeyBase58":"zxt6NyoorFUFMXA8mDBULjnuH3v6iNdZm42PyG4c1YdC"
                      },
					{
					   "id": "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#master",
					   "type":"ECDSAsecp256r1",
					   "controller":"did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN",
					   "publicKeyBase58":"zNxoZaZLdackZQNMas7sCkPRHZsJ3BtdjEvM2y5gNvKJ"
				   }
                    ],
        "authentication":["did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j#default",
                          {
                               "id": "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default",
                               "type":"ECDSAsecp256r1",
                               "controller":"did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN",
                               "publicKeyBase58":"zNxoZaZLdackZQNMas7sCkPRHZsJ3BtdjEvM2y5gNvKJ"
                           }
                         ],
        "authorization":["did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default"],
        "expires" : "2023-02-10T17:00:00Z"
	}`)

//right
var didPayloadInfoBytes = []byte(
	`{
    "header":{
        "specification":"elastos/did/1.0",
        "operation":"create"
    },
    "payload":"eyJpZCI6ImRpZDplbGFzdG9zOmlkd3VFTWNjU3BzVEg0WnFyaHVIcWc2eThYTVZRQXNZNWciLCJwdWJsaWNLZXkiOlt7ImlkIjoiZGlkOmVsYXN0b3M6aWR3dUVNY2NTcHNUSDRacXJodUhxZzZ5OFhNVlFBc1k1ZyNwcmltYXJ5IiwidHlwZSI6IkVDRFNBc2VjcDI1NnIxIiwiY29udHJvbGxlciI6ImRpZDplbGFzdG9zOmlkd3VFTWNjU3BzVEg0WnFyaHVIcWc2eThYTVZRQXNZNWciLCJwdWJsaWNLZXlCYXNlNTgiOiJrVFlRaE10b2ltbTl3VjN2eTRxOUVWeTRaMVd4UnF4aHZuZ3p0ZEdvMURtYyJ9XSwiYXV0aGVudGljYXRpb24iOlsiZGlkOmVsYXN0b3M6aWR3dUVNY2NTcHNUSDRacXJodUhxZzZ5OFhNVlFBc1k1ZyNwcmltYXJ5Il0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbeyJpZCI6ImRpZDplbGFzdG9zOmlkd3VFTWNjU3BzVEg0WnFyaHVIcWc2eThYTVZRQXNZNWcjcHJvZmlsZSIsInR5cGUiOlsiU2VsZlByb2NsYWltZWRDcmVkZW50aWFsIl0sImlzc3VlciI6ImRpZDplbGFzdG9zOmlkd3VFTWNjU3BzVEg0WnFyaHVIcWc2eThYTVZRQXNZNWciLCJpc3N1YW5jZURhdGUiOiIyMDIxLTAxLTI4VDA2OjM4OjM1WiIsImV4cGlyYXRpb25EYXRlIjoiMjAyNi0wMS0yOFQwNjozODozNVoiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDplbGFzdG9zOmlkd3VFTWNjU3BzVEg0WnFyaHVIcWc2eThYTVZRQXNZNWciLCJlbWFpbCI6ImpvaG5AZXhhbXBsZS5jb20iLCJnZW5kZXIiOiJNYWxlIiwibGFuZ3VhZ2UiOiJFbmdsaXNoIiwibmFtZSI6IkpvaG4iLCJuYXRpb24iOiJTaW5nYXBvcmUiLCJ0d2l0dGVyIjoiQGpvaG4ifSwicHJvb2YiOnsidHlwZSI6IkVDRFNBc2VjcDI1NnIxIiwiY3JlYXRlZCI6IjIwMjEtMDEtMjhUMDY6Mzg6MzVaIiwidmVyaWZpY2F0aW9uTWV0aG9kIjoiZGlkOmVsYXN0b3M6aWR3dUVNY2NTcHNUSDRacXJodUhxZzZ5OFhNVlFBc1k1ZyNwcmltYXJ5Iiwic2lnbmF0dXJlIjoidWJSajNMNVp0LWZpUE4wT1dGLWZyQjlfZ2xHNWlHR1BFUzJKelNKWDhIX1M2bXotUnFQOTZzYXduYUVFdkN6Ym9NdHVnRlQxOXZTNC0xQnVLTlZRVGcifX1dLCJleHBpcmVzIjoiMjAyNi0wMS0yOFQwNjozODozNVoiLCJwcm9vZiI6eyJ0eXBlIjoiRUNEU0FzZWNwMjU2cjEiLCJjcmVhdGVkIjoiMjAyMS0wMS0yOFQwNjozODozNVoiLCJjcmVhdG9yIjoiZGlkOmVsYXN0b3M6aWR3dUVNY2NTcHNUSDRacXJodUhxZzZ5OFhNVlFBc1k1ZyNwcmltYXJ5Iiwic2lnbmF0dXJlVmFsdWUiOiI3d2Z3dF9ZOGpZamo2Sm01NExFa2VKbk91bHItNHprMmRtRDBLalhxd2NaV0NnUU1Mb0lRR0ZwUVlmODA0ZFlvbmsxcTNTMFQ1UlZaNTdTRWVVN01qdyJ9fQ",
    "proof":{
        "type":"ECDSAsecp256r1",
        "verificationMethod":"did:elastos:idwuEMccSpsTH4ZqrhuHqg6y8XMVQAsY5g#primary",
        "signature":"yaZ7rX0G0JhVlK0xEprcEa93Lu3E5nQJww_jQuCQb8hSl3h3JFB3KegDvSq8KUtSS1szN5dsImV0IuAIccOPxw"
    }
}
`)

var errDIDPayloadInfoBytes = []byte(
	`{
		"header":{"operation":"create","specification":"elastos/did/1.0"},
		"payload":"eyJpZCI6ImRpZDplbGFzdG9zOmlZUTZ1alBjd21UWmZqMmtOZmZXNEJDeXRKenlqbUpkRGQiLCJwdWJsaWNLZXkiOlt7ImlkIjoiI3ByaW1hcnkiLCJwdWJsaWNLZXlCYXNlNTgiOiJ6S1JYMWtOWGVYeTVuS3NyVTVtdVR3Z2Y3ZlhRYnhXZzdpUUtCdnBlS0dCUCJ9XSwiYXV0aGVudGljYXRpb24iOlsiI3ByaW1hcnkiXX0",
		"proof":{
			"signature":"nrbHEEysMLzBR1mMVRjan9yfQtNGmK6Rqy7v9rvUpsJNoIMsY5JtEUiJvW82jW4xNlvOOEDI-VpLK_GCgjoUdQ",
			"verificationMethod":"#primary"
			}
	 }
`)

func LoadJsonData(fileName string) ([]byte, error) {
	fileData, err := ioutil.ReadFile(fileName)
	if err != nil {
		return []byte{}, err
	}
	return fileData, nil

}

func TestCheckDIDDIDPayload(t *testing.T) {
	//no create ------>update
	payloadUpdateDIDInfo := getPayloadUpdateDID()
	data, err := json.Marshal(payloadUpdateDIDInfo)
	assert.NoError(t, err)
	err = checkDIDTransaction(data, nil)
	assert.EqualError(t, err, "DID WRONG OPERATION NOT EXIST")

	////doubale create
	payloadCreate := getPayloadCreateDID()
	data, err = json.Marshal(payloadCreate)
	assert.NoError(t, err)
	err = checkDIDTransaction(data, nil)
	assert.NoError(t, err)
}

func TestCommonDIDPayloadOperation(t *testing.T) {
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
	payloadCreate := getPayloadCreateDID()
	data, err := json.Marshal(payloadCreate)
	assert.NoError(t, err)
	err = checkDIDTransaction(data, statedb)
	assert.NoError(t, err)

	buf := new(bytes.Buffer)
	payloadCreate.Serialize(buf, did.DIDVersion)
	receipt := getCreateDIDReceipt(*payloadCreate, common.Hash{})
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueWriter), common.Hash{}, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(common.Hash{})

	payloadUpdate := payloadCreate
	payloadUpdate.Header.Operation = did.Update_DID_Operation
	payloadUpdate.Header.PreviousTxid = common.Hash{}.String()
	payloadUpdate.Header.PreviousTxid = payloadUpdate.Header.PreviousTxid[2:]
	privateKey1, _ := elacom.HexStringToBytes(PayloadPrivateKey)
	sign, _ := elaCrypto.Sign(privateKey1, payloadUpdate.GetData())
	payloadUpdate.Proof.Signature = base64url.EncodeToString(sign)

	data, err = json.Marshal(payloadUpdate)
	assert.NoError(t, err)
	err = checkDIDTransaction(data, statedb)
	assert.NoError(t, err)
	statedb.RemoveDIDLog(common.Hash{})

	didWithPrefix := payloadUpdate.DIDDoc.ID
	verifDid := didWithPrefix + "#default"
	deactivePayLoad := getPayloadDeactivateDID(didWithPrefix, verifDid)
	data, err = json.Marshal(deactivePayLoad)
	assert.NoError(t, err)
	err = checkDIDTransaction(data, statedb)
	assert.NoError(t, err)
}

func getPayloadUpdateDID() *did.DIDPayload {
	info := new(did.DIDDoc)
	json.Unmarshal(didPayloadBytes, info)

	return &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     "update",
		},
		Payload: base64url.EncodeToString(didPayloadBytes),
		Proof: did.Proof{
			Type:               randomString(),
			VerificationMethod: randomString(),
			Signature:          randomString(),
		},
		DIDDoc: info,
	}
}

func randomString() string {
	a := make([]byte, 20)
	rand.Read(a)
	return elacom.BytesToHexString(a)
}

func TestIDChainStore_CreateDIDTx(t *testing.T) {
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
	evm.chainConfig.OldDIDMigrateHeight = new(big.Int).SetInt64(2)
	evm.chainConfig.OldDIDMigrateAddr = "0xC445f9487bF570fF508eA9Ac320b59730e81e503"
	evm.chainConfig.CustomizeDIDHeight = big.NewInt(0)
	evm.chainConfig.CheckCustomizeDIDBeginHeight = big.NewInt(0)

	evm.chainConfig.MaxExpiredHeight = big.NewInt(100)

	evm.BlockNumber = new(big.Int).SetInt64(1)
	//2021 09 24 unix 1632450124
	evm.Time = new(big.Int).SetInt64(1632450124)
	evm.Context.Origin = common.HexToAddress("0xC445f9487bF570fF508eA9Ac320b59730e81e503")

	doc := getPayloadCreateDID()
	var gas uint64 = 2000
	payloadJson, err := json.Marshal(doc)
	assert.NoError(t, err)
	err = checkDIDTransaction(payloadJson, nil)
	assert.NoError(t, err)

	info := new(did.DIDPayload)
	json.Unmarshal(didPayloadInfoBytes, info)
	payloadBase64, _ := base64url.DecodeString(info.Payload)
	payloadInfo := new(did.DIDDoc)
	json.Unmarshal(payloadBase64, payloadInfo)
	info.DIDDoc = payloadInfo

	err = checkDIDTransaction(didPayloadInfoBytes, nil)
	assert.NoError(t, err)

	originExpires := info.DIDDoc.Expires

	info.DIDDoc.Expires = "Mon Jan _2 15:04:05 2006"
	err = checkRegisterDID(evm, info, gas)
	assert.EqualError(t, err, "invalid Expires format")

	info.DIDDoc.Expires = "2006-01-02T15:04:05Z07:00"
	err = checkRegisterDID(evm, info, gas)
	assert.EqualError(t, err, "invalid Expires format")

	info.DIDDoc.Expires = originExpires
	err = checkRegisterDID(evm, info, gas)
	assert.NoError(t, err)

	info = new(did.DIDPayload)
	json.Unmarshal(errDIDPayloadInfoBytes, info)

	payloadBase64, _ = base64url.DecodeString(info.Payload)
	payloadInfo = new(did.DIDDoc)
	json.Unmarshal(payloadBase64, payloadInfo)
	info.DIDDoc = payloadInfo

	data, err := json.Marshal(info)
	assert.NoError(t, err)
	err = checkDIDTransaction(data, statedb)
	assert.EqualError(t, err, "invalid Expires format")
}

func TestCheckRegisterDID(t *testing.T) {
	id1 := "did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
	privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"

	id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"

	tx2 := getPayloadDIDInfo(id2, "create", issuerDocByts, privateKey2Str)
	tx1 := getPayloadDIDInfo(id1, "create", docDocBytes, privateKey1Str)

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
	receipt := getCreateDIDReceipt(*tx2, common.Hash{})
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 0, types.Receipts{receipt}, 0)

	didParam.CustomIDFeeRate = 0
	statedb.RemoveDIDLog(common.Hash{})

	docBytes, err := json.Marshal(tx2)
	assert.NoError(t, err)

	err2 := checkDIDTransaction(docBytes, statedb)
	assert.EqualError(t, err2, "DID WRONG OPERATION ALREADY EXIST")

	docBytes, err = json.Marshal(tx1)
	assert.NoError(t, err)
	err3 := checkDIDTransaction(docBytes, statedb)
	assert.NoError(t, err3)

}

//did doc and vc with context
func TestCheckRegisterDIDWithContext(t *testing.T) {

	id1 := "did:elastos:idwuEMccSpsTH4ZqrhuHqg6y8XMVQAsY5g"
	privateKey1Str := "AqBB8Uur4QwwBtFPeA2Yd5yF2Ni45gyz2osfFcMcuP7J"
	tx1 := getPayloadDIDInfo(id1, "create", user2IDDocByts, privateKey1Str)
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	docBytes, err := json.Marshal(tx1)
	assert.NoError(t, err)
	err3 := checkDIDTransactionWithPayloadSyntax(docBytes, statedb)
	assert.NoError(t, err3)

}

func getPayloadDIDInfo(id string, didOperation string, docBytes []byte, privateKeyStr string) *did.DIDPayload {
	//pBytes := getDIDPayloadBytes(id)
	info := new(did.DIDDoc)
	json.Unmarshal(docBytes, info)
	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     didOperation,
		},
		Payload: base64url.EncodeToString(docBytes),
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: id + "#primary", //"did:elastos:" + primary
		},
		DIDDoc: info,
	}
	privateKey1 := base58.Decode(privateKeyStr)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}

func getPayloadDIDInfoWithPayloadURI(id string, didOperation string, docBytes []byte, privateKeyStr, PayloadURI string) *did.DIDPayload {
	//pBytes := getDIDPayloadBytes(id)
	info := new(did.DIDDoc)
	json.Unmarshal(docBytes, info)
	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     didOperation,
		},
		Payload: base64url.EncodeToString(docBytes),
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: id + PayloadURI, //"did:elastos:" + primary
		},
		DIDDoc: info,
	}
	privateKey1 := base58.Decode(privateKeyStr)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}

func getPayloadCreateDID() *did.DIDPayload {
	info := new(did.DIDDoc)
	json.Unmarshal(didPayloadBytes, info)
	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     "create",
		},
		Payload: base64url.EncodeToString(didPayloadBytes),
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: "did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j#default",
		},
		DIDDoc: info,
	}

	privateKey1, _ := elacom.HexStringToBytes(PayloadPrivateKey)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}

func getCreateDIDReceipt(payload did.DIDPayload, txID common.Hash) *types.Receipt {
	id := payload.DIDDoc.ID
	buf := new(bytes.Buffer)
	payload.Serialize(buf, did.DIDVersion)
	receipt := &types.Receipt{
		Status:            1,
		CumulativeGasUsed: 1,
		Logs:              []*types.Log{},
		TxHash:            common.Hash{},

		DIDLog: types.DIDLog{
			DID:       id,
			Operation: payload.Header.Operation,
			Data:      buf.Bytes(),
			TxHash:    txID,
		},
	}
	return receipt
}

func getDeactiveDIDReceipt(payload did.DIDPayload) *types.Receipt {
	id := payload.Payload
	payload.Payload = base64url.EncodeToString([]byte(payload.Payload))
	buf := new(bytes.Buffer)
	payload.Serialize(buf, did.DIDVersion)
	receipt := &types.Receipt{
		Status:            1,
		CumulativeGasUsed: 1,
		Logs:              []*types.Log{},
		TxHash:            common.Hash{},

		DIDLog: types.DIDLog{
			DID:       id,
			Operation: payload.Header.Operation,
			Data:      buf.Bytes(),
		},
	}
	return receipt
}

func getDeclareDIDReceipt(payload did.DIDPayload) *types.Receipt {
	id := payload.Payload
	buf := new(bytes.Buffer)
	payload.Serialize(buf, did.DIDVersion)
	receipt := &types.Receipt{
		Status:            1,
		CumulativeGasUsed: 1,
		Logs:              []*types.Log{},
		TxHash:            common.Hash{},
		DIDLog: types.DIDLog{
			DID:       id,
			Operation: payload.Header.Operation,
			Data:      buf.Bytes(),
		},
	}
	return receipt
}

func TestIDChainStore_DeactivateDIDTx(t *testing.T) {
	didWithPrefix := "did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j"
	verifDid := "did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j#default"
	id := didWithPrefix

	txCreateDID := getPayloadCreateDID()
	payload := getPayloadDeactivateDID(didWithPrefix, verifDid)

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.BlockNumber = new(big.Int).SetInt64(0)
	receipt := getDeactiveDIDReceipt(*payload)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 0, types.Receipts{receipt}, 0)
	//Deactive did  have no
	err := checkDeactivateDID(evm, payload)
	assert.EqualError(t, err, ErrNotFound.Error())

	buf := new(bytes.Buffer)
	txCreateDID.Serialize(buf, did.DIDVersion)
	receipt = getCreateDIDReceipt(*txCreateDID, common.Hash{})
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 0, types.Receipts{receipt}, 0)
	statedb.AddDIDLog(id, did.Create_DID_Operation, buf.Bytes())
	statedb.RemoveDIDLog(common.Hash{})
	err = checkDeactivateDID(evm, payload)
	assert.NoError(t, err)

	//wrong public key to verify sign
	verifDid = "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#master"
	payload = getPayloadDeactivateDID(didWithPrefix, verifDid)
	err = checkDeactivateDID(evm, payload)
	assert.EqualError(t, err, "not found")

	//deactive one deactivated did
	statedb.AddDIDLog(id, did.Deactivate_DID_Operation, buf.Bytes())
	rawdb.PersistDeactivateDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore),
		statedb.GetDIDLog(common.Hash{}), common.Hash{})
	statedb.RemoveDIDLog(common.Hash{})
	txDeactivateWrong := getPayloadDeactivateDID(didWithPrefix, verifDid)
	err = checkDeactivateDID(evm, txDeactivateWrong)
	assert.EqualError(t, err, "DID WAS AREADY DEACTIVE")

}

func TestDeactivateCustomizeDIDTx(t *testing.T) {
	{
		didParam.IsTest = true
		defer func() {
			didParam.IsTest = false
		}()
		//save ctr1 doc to db
		idUser1 := "did:elastos:ijb8oNP3ZMKP6N5swJCoiYtoUbomAK13Xy"
		privateKeyUser1Str := "78cQWUwaqVHnn7JLE7xNjmDcEYyU4fnMuq6jPTUYsdi"
		tx1 := getPayloadDIDInfo(idUser1, "create", jianbinCtrl1PubKeyTest, privateKeyUser1Str)
		statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
		evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
		evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
		evm.Time = big.NewInt(0)
		evm.BlockNumber = new(big.Int).SetInt64(3)
		evm.chainConfig.DocArraySortHeight = new(big.Int).SetInt64(2)
		buf := new(bytes.Buffer)
		tx1.Serialize(buf, did.DIDVersion)
		statedb.AddDIDLog(idUser1, did.Create_DID_Operation, buf.Bytes())
		receipt := getCreateDIDReceipt(*tx1, common.Hash{})
		rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 100, types.Receipts{receipt}, 123456)
		statedb.RemoveDIDLog(common.Hash{})

		//save ctr2 doc to db
		privateKeyUser2Str := "4fDnYELy1um12fQPA7V6U953tdMwoUVTsAM5Lp5RF1AU"
		idUser2 := "did:elastos:iidhLBRtSLMzsAuK3uHveLccTfZtCwRreh"
		tx2 := getPayloadDIDInfo(idUser2, "create", jianbinCtrl2PubKeyTest, privateKeyUser2Str)
		hash1 := common.HexToHash("0x1234")
		buf = new(bytes.Buffer)
		tx2.Serialize(buf, did.DIDVersion)
		statedb.Prepare(hash1, hash1, 1)
		statedb.AddDIDLog(idUser2, did.Create_DID_Operation, buf.Bytes())
		receipt = getCreateDIDReceipt(*tx2, hash1)
		rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), hash1, 100, types.Receipts{receipt}, 123456)
		statedb.RemoveDIDLog(hash1)

		//save ctr3 doc to db
		privateKeyUser3Str := "4fDnYELy1um12fQPA7V6U953tdMwoUVTsAM5Lp5RF1AU"
		idUser3 := "did:elastos:iidhLBRtSLMzsAuK3uHveLccTfZtCwRreh"
		tx3 := getPayloadDIDInfo(idUser3, "create", jianbinCtrl3PubKeyTest, privateKeyUser3Str)
		hash3 := common.HexToHash("0x1234567")
		buf = new(bytes.Buffer)
		tx3.Serialize(buf, did.DIDVersion)
		statedb.Prepare(hash3, hash3, 1)
		statedb.AddDIDLog(idUser3, did.Create_DID_Operation, buf.Bytes())
		receipt = getCreateDIDReceipt(*tx3, hash3)
		rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), hash3, 100, types.Receipts{receipt}, 123456)
		statedb.RemoveDIDLog(hash3)

		//save customized did  did:elastos:Lindalittlefish05
		privateKeyUser4Str := "4fDnYELy1um12fQPA7V6U953tdMwoUVTsAM5Lp5RF1AU"
		idUser4 := "did:elastos:Lindalittlefish05"
		tx4 := getPayloadDIDInfo(idUser4, "create", custmizeDIDMultyCtrlTest, privateKeyUser4Str)
		hash4 := common.HexToHash("0x123456789")
		buf = new(bytes.Buffer)
		tx4.Serialize(buf, did.DIDVersion)
		statedb.Prepare(hash4, hash4, 1)
		statedb.AddDIDLog(idUser4, did.Create_DID_Operation, buf.Bytes())
		receipt = getCreateDIDReceipt(*tx4, hash4)

		rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), hash4, 100, types.Receipts{receipt}, 123456)
		statedb.RemoveDIDLog(hash4)

		customizedid := idUser4
		//customized deactive use controller1 primarykey
		{
			verifDid := idUser1 + "#primary"
			payload := getPayloadDeactivateDIDFin(customizedid, verifDid, privateKeyUser1Str)
			err := checkDeactivateDID(evm, payload)
			assert.NoError(t, err)
		}
	}

}

func getPayloadDeactivateDID(id, verifDid string) *did.DIDPayload {
	info := new(did.DIDDoc)
	json.Unmarshal(didPayloadBytes, info)

	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     did.Deactivate_DID_Operation,
		},
		Payload: id,
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: verifDid,
		},
	}
	privateKey1 := common.Hex2Bytes(PayloadPrivateKey)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}

func getPayloadDeactivateDIDFin(id, PayloadVMPubKeyURI, PayloadVMPriKey string) *did.DIDPayload {
	info := new(did.DIDDoc)
	json.Unmarshal(didPayloadBytes, info)

	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     did.Deactivate_DID_Operation,
		},
		Payload: id,
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: PayloadVMPubKeyURI,
		},
	}
	//
	privateKey1 := base58.Decode(PayloadVMPriKey)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	fmt.Println("getPayloadDeactivateDIDFin PayloadVMPubKeyURI", PayloadVMPubKeyURI)

	fmt.Println("getPayloadDeactivateDIDFin PayloadVMPriKey", PayloadVMPriKey)
	fmt.Println("getPayloadDeactivateDIDFin GetData", string(p.GetData()))
	fmt.Println("getPayloadDeactivateDIDFin Signature", p.Proof.Signature)
	return p
}

//issuer.json SelfProclaimedCredential
func TestSelfProclaimedCredential(t *testing.T) {
	privateKey3Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	id3 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"

	didParam.CustomIDFeeRate = 0
	//id3DocBytes
	tx3 := getPayloadDIDInfo(id3, "create", issuerDocByts, privateKey3Str)
	data, err := json.Marshal(tx3)
	assert.NoError(t, err)
	err3 := checkDIDTransaction(data, nil)
	assert.NoError(t, err3)

	tx3_2 := getPayloadDIDInfo(id3, "create", issuerDocByts, privateKey3Str)
	data, err = json.Marshal(tx3_2)
	assert.NoError(t, err)
	err3_2 := checkDIDTransaction(data, nil)
	assert.NoError(t, err3_2)
}

func TestCustomizedDID(t *testing.T) {
	id1 := "did:elastos:imUUPBfrZ1yZx6nWXe6LNN59VeX2E6PPKj"
	privateKey1Str := "413uivqLEMjPd8bo42K9ic6VXpgYcJLEwB3vefxJDhXJ" //413uivqLEMjPd8bo42K9ic6VXpgYcJLEwB3vefxJDhXJ
	tx1 := getPayloadDIDInfo(id1, "create", id11DocByts, privateKey1Str)

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
	evm.BlockNumber = new(big.Int).SetInt64(1)
	evm.chainConfig.DocArraySortHeight = new(big.Int).SetInt64(2)
	evm.chainConfig.CustomizeDIDHeight = big.NewInt(3000000)
	evm.chainConfig.CheckCustomizeDIDBeginHeight = big.NewInt(0)
	evm.chainConfig.MaxExpiredHeight = big.NewInt(100)

	evm.Time = big.NewInt(0)
	buf := new(bytes.Buffer)
	tx1.Serialize(buf, did.DIDVersion)

	statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
	statedb.RemoveDIDLog(common.Hash{})

	//examplercorp.id.json
	didParam.IsTest = true
	tx3 := getCustomizedDIDDoc(id1, "create", customizedDIDDocSingleContrller, privateKey1Str)

	receipt := getCreateDIDReceipt(*tx1, common.Hash{})
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 0, types.Receipts{receipt}, 0)

	didParam.CustomIDFeeRate = 0
	err3 := checkCustomizedDID(evm, tx3, 20000)
	assert.NoError(t, err3)

	didParam.IsTest = false
}

//issuer.json SelfProclaimedCredential
func TestCustomizedDIDMultSign(t *testing.T) {
	didParam.IsTest = true

	defer func() {
		didParam.IsTest = false
	}()
	idUser1 := "did:elastos:iXcRhYB38gMt1phi5JXJMjeXL2TL8cg58y"
	privateKeyUser1Str := "3z2QFDJE7woSUzL6az9sCB1jkZtzfvEZQtUnYVgQEebS"
	tx1 := getPayloadDIDInfo(idUser1, "create", user1IDDocByts, privateKeyUser1Str)

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
	evm.Time = big.NewInt(0)
	evm.BlockNumber = new(big.Int).SetInt64(1)
	evm.chainConfig.DocArraySortHeight = new(big.Int).SetInt64(2)
	evm.chainConfig.CustomizeDIDHeight = big.NewInt(3000000)
	evm.chainConfig.CheckCustomizeDIDBeginHeight = big.NewInt(0)

	evm.chainConfig.MaxExpiredHeight = big.NewInt(100)

	buf := new(bytes.Buffer)
	tx1.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(idUser1, did.Create_DID_Operation, buf.Bytes())
	receipt := getCreateDIDReceipt(*tx1, common.Hash{})
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 0, types.Receipts{receipt}, 0)

	statedb.RemoveDIDLog(common.Hash{})

	privateKeyUser2Str := "AqBB8Uur4QwwBtFPeA2Yd5yF2Ni45gyz2osfFcMcuP7J"
	idUser2 := "did:elastos:idwuEMccSpsTH4ZqrhuHqg6y8XMVQAsY5g"
	tx2 := getPayloadDIDInfo(idUser2, "create", user2IDDocByts, privateKeyUser2Str)

	hash1 := common.HexToHash("0x1234")
	buf = new(bytes.Buffer)
	tx2.Serialize(buf, did.DIDVersion)
	statedb.Prepare(hash1, hash1, 1)
	statedb.AddDIDLog(idUser2, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*tx2, hash1)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), hash1, 0, types.Receipts{receipt}, 0)

	statedb.RemoveDIDLog(hash1)

	CustomizedDIDTx2 := getCustomizedDIDDocMultiSign(idUser1, idUser2, "create", customizedDIDDocBytes2,
		privateKeyUser1Str, privateKeyUser2Str)
	didParam.CustomIDFeeRate = 0
	err := checkCustomizedDID(evm, CustomizedDIDTx2, 20000)
	assert.NoError(t, err)
}

func getCustomizedDIDDocMultiSign(id1, id2 string, didDIDPayload string, docBytes []byte,
	privateKeyStr1, privateKeyStr2 string) *did.DIDPayload {
	info := new(did.DIDDoc)
	json.Unmarshal(docBytes, info)

	//var Proofs []*types.Proof
	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     didDIDPayload,
		},
		Payload: base64url.EncodeToString(docBytes),
		DIDDoc:  info,
	}
	proof1 := &did.Proof{
		Type:               "ECDSAsecp256r1",
		VerificationMethod: id1 + "#primary", //"did:elastos:" +
	}
	privateKey1 := base58.Decode(privateKeyStr1)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	proof1.Signature = base64url.EncodeToString(sign)
	p.Proof = *proof1
	return p
}

func getCustomizedDIDDocMultiSignFinal(payloadVMKey, operation, payloadPriKey string, docBytes []byte) *did.DIDPayload {
	info := new(did.DIDDoc)
	json.Unmarshal(docBytes, info)

	//var Proofs []*types.Proof
	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     operation,
		},
		Payload: base64url.EncodeToString(docBytes),
		DIDDoc:  info,
	}
	proof1 := &did.Proof{
		Type:               "ECDSAsecp256r1",
		VerificationMethod: payloadVMKey, //"did:elastos:" +
	}
	privateKey1 := base58.Decode(payloadPriKey)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	proof1.Signature = base64url.EncodeToString(sign)
	p.Proof = *proof1
	return p
}

func getCustomizedDIDDoc(id string, didDIDPayload string, docBytes []byte,
	privateKeyStr string) *did.DIDPayload {
	//pBytes := getDIDPayloadBytes(id)
	info := new(did.DIDDoc)
	json.Unmarshal(docBytes, info)

	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     didDIDPayload,
		},
		Payload: base64url.EncodeToString(docBytes),
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: id + "#primary", //"did:elastos:" +
		},
		DIDDoc: info,
	}
	privateKey1 := base58.Decode(privateKeyStr)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}

//didDIDPayload must be create or update
func getIDVerifiableCredentialTx(id string, didDIDPayload string, docBytes []byte,
	privateKeyStr string) *did.DIDPayload {
	fmt.Println(" ---docBytes--- ", string(docBytes))
	info := new(did.VerifiableCredentialDoc)
	json.Unmarshal(docBytes, info)

	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     didDIDPayload,
		},
		Payload: base64url.EncodeToString(docBytes),
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: id + "#primary",
		},
		CredentialDoc: info,
	}
	privateKey1 := base58.Decode(privateKeyStr)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}

//didDIDPayload must be create or update
func getRevokeVerifiableCredentialTx(VMKey, IDVerCre, privateKeyStr string) *did.DIDPayload {
	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     "revoke",
		},
		Payload: IDVerCre,
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: VMKey,
		},
	}
	privateKey1 := base58.Decode(privateKeyStr)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}

//todo complete the test
//self verifiable credential
func Test0DIDVerifiableCredentialTx(t *testing.T) {
	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	//id2 := "ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	tx2 := getPayloadDIDInfo(id2, "create", issuerDocByts, privateKey2Str)

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
	buf := new(bytes.Buffer)
	tx2.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id2, did.Create_DID_Operation, buf.Bytes())
	receipt := getCreateDIDReceipt(*tx2, common.Hash{})
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(common.Hash{})

	hash3 := common.HexToHash("0x3456")
	statedb.Prepare(hash3, hash3, 1)
	privateKey3Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	//id2 := "ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	id3 := "did:elastos:igXiyCJEUjGJV1DMsMa4EbWunQqVg97GcS"
	tx3 := getPayloadDIDInfo(id3, "create", user3IDDocByts, privateKey3Str)
	buf = new(bytes.Buffer)
	tx3.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id3, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*tx3, hash3)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), hash3, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash3)

	//did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB
	//
	verifableCredentialTx := getIDVerifiableCredentialTx("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB",
		"declare",
		didVerifCred, privateKey2Str)

	jsonData, err := json.Marshal(verifableCredentialTx)
	assert.NoError(t, err)
	err = checkDIDTransaction(jsonData, statedb)
	assert.NoError(t, err)
}

//self verifiable credential
func TestRevokeVerifiableCredentialTx(t *testing.T) {
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	db := statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore)
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.BlockNumber = new(big.Int).SetInt64(1)
	evm.chainConfig.DocArraySortHeight = new(big.Int).SetInt64(2)
	evm.Time = big.NewInt(0)

	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	tx2 := getPayloadDIDInfo(id2, "create", issuerDocByts, privateKey2Str)

	buf := new(bytes.Buffer)
	tx2.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id2, did.Create_DID_Operation, buf.Bytes())
	receipt := getCreateDIDReceipt(*tx2, common.Hash{})
	rawdb.WriteReceipts(db, common.Hash{}, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(common.Hash{})

	verifableCredentialTx := getIDVerifiableCredentialTx("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB",
		"declare",
		didVerifCred, privateKey2Str)
	fmt.Println(verifableCredentialTx)
	err := checkCredentialTX(evm, verifableCredentialTx)
	assert.NoError(t, err)

}

// one cotroller
func TestRevokeCustomizedDIDVerifiableCredentialTx(t *testing.T) {
	id1 := "did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
	privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"
	tx1 := getPayloadDIDInfo(id1, "create", docDocBytes, privateKey1Str)

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	//evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})

	buf := new(bytes.Buffer)
	tx1.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
	receipt := getCreateDIDReceipt(*tx1, common.Hash{})
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 0, types.Receipts{receipt}, 0)

	thash, err := elacom.Uint256FromBytes(common.Hash{}.Bytes())
	if err != nil {
		fmt.Println("PersistRegisterDIDTx Uint256FromBytes err", "thash", thash, "err", err)
	}

	statedb.RemoveDIDLog(common.Hash{})

	id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	tx2 := getPayloadDIDInfo(id2, "create", issuerDocByts, privateKey2Str)

	buf = new(bytes.Buffer)
	tx2.Serialize(buf, did.DIDVersion)
	tx2hash := common.HexToHash("0x1234")
	statedb.Prepare(tx2hash, tx2hash, 1)
	statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*tx2, tx2hash)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), tx2hash, 0, types.Receipts{receipt}, 0)

	statedb.RemoveDIDLog(tx2hash)

	tx3hash := common.HexToHash("0x2345")
	statedb.Prepare(tx3hash, tx3hash, 1)
	CustomizedDIDTx1 := getCustomizedDIDTx(id1, "create", custIDSingleSignDocBytes1, privateKey1Str)
	buf = new(bytes.Buffer)
	CustomizedDIDTx1.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*CustomizedDIDTx1, tx3hash)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), tx3hash, 0, types.Receipts{receipt}, 0)
	thash3, err := elacom.Uint256FromBytes(tx3hash.Bytes())
	if err != nil {
		fmt.Println("PersistRegisterDIDTx Uint256FromBytes err", "thash3", thash3, "err", err)
	}
	statedb.RemoveDIDLog(tx3hash)

	verifableCredentialTx := getIDVerifiableCredentialTx(id1, "declare", custIDVerifCredDocBytes, privateKey1Str)
	data, err := json.Marshal(verifableCredentialTx)
	assert.NoError(t, err)
	err = checkDIDTransaction(data, statedb)
	assert.NoError(t, err)

	tx4Hash := common.HexToHash("0x3456")
	credentialID := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile"
	buf = new(bytes.Buffer)
	statedb.Prepare(tx4Hash, tx4Hash, 1)
	verifableCredentialTx.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(credentialID, did.Declare_Verifiable_Credential_Operation, buf.Bytes())
	receipt = getDeclareDIDReceipt(*verifableCredentialTx)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), tx4Hash, 0, types.Receipts{receipt}, 0)
	thash4, err := elacom.Uint256FromBytes(tx4Hash.Bytes())
	if err != nil {
		fmt.Println("PersistRegisterDIDTx Uint256FromBytes err", "thash4", thash4, "err", err)
	}
	rawdb.PersistRegisterDIDPayload(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), *thash4, verifableCredentialTx)
	err4 := rawdb.PersistVerifiableCredentialTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(tx4Hash), 100, 123456, tx4Hash)
	assert.NoError(t, err4)

	//iWFAUYhTa35c1fPe3iCJvihZHx6quumnym
	//the issuer revoke the credential
	verifableCredentialRevokeTx := getRevokeVerifiableCredentialTx("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#primary",
		"did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile", privateKey2Str)
	data, err5 := json.Marshal(verifableCredentialRevokeTx)
	assert.NoError(t, err5)
	err5 = checkDIDTransaction(data, statedb)
	assert.NoError(t, err5)
}

// declare after real revoke
func TestRevokeBeforeRegisterVerifiableCredentialTx(t *testing.T) {
	id1 := "did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
	privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"
	id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.BlockNumber = new(big.Int).SetInt64(1)
	evm.chainConfig.DocArraySortHeight = new(big.Int).SetInt64(2)
	db := statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore)
	buf := new(bytes.Buffer)

	//regisgter iWFAUYhTa35c1fPe3iCJvihZHx6quumnym
	hash1 := common.HexToHash("0x1234")
	statedb.Prepare(hash1, hash1, 1)
	tx1 := getPayloadDIDInfo(id1, "create", docDocBytes, privateKey1Str)
	buf = new(bytes.Buffer)
	tx1.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
	receipt := getCreateDIDReceipt(*tx1, hash1)
	rawdb.WriteReceipts(db, hash1, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash1)
	{
		id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
		privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
		tx2 := getPayloadDIDInfo(id2, "create", issuerDocByts, privateKey2Str)

		buf = new(bytes.Buffer)
		tx2.Serialize(buf, did.DIDVersion)
		tx2hash := common.HexToHash("0x1234678")
		statedb.Prepare(tx2hash, tx2hash, 1)
		statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
		receipt = getCreateDIDReceipt(*tx2, tx2hash)
		rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), tx2hash, 0, types.Receipts{receipt}, 0)
		statedb.RemoveDIDLog(tx2hash)
	}

	//	regisgter did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB
	hash2 := common.HexToHash("0x2345")
	statedb.Prepare(hash2, hash2, 1)
	tx2 := getPayloadDIDInfo(id2, "create", issuerDocByts, privateKey2Str)
	buf = new(bytes.Buffer)
	tx2.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id2, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*tx2, hash2)
	rawdb.WriteReceipts(db, hash2, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash2)

	//ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB is the issuer
	verifableCredentialRevokeTx := getRevokeVerifiableCredentialTx("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#primary",
		"did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile", privateKey2Str)
	err := checkCredentialTX(evm, verifableCredentialRevokeTx)
	assert.NoError(t, err)
	credentialID := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile"
	hash := common.Hash{}
	statedb.Prepare(hash, hash, 1)
	buf = new(bytes.Buffer)
	verifableCredentialRevokeTx.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(credentialID, did.Revoke_Verifiable_Credential_Operation, buf.Bytes())
	receipt = getDeclareDIDReceipt(*verifableCredentialRevokeTx)
	rawdb.WriteReceipts(db, hash, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash)

	hash3 := common.HexToHash("3456")
	statedb.Prepare(hash3, hash3, 1)
	CustomizedDIDTx1 := getCustomizedDIDTx(id1, "create", custIDSingleSignDocBytes1, privateKey1Str)
	customizedDID := "did:elastos:foobar"
	buf = new(bytes.Buffer)
	CustomizedDIDTx1.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(customizedDID, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*CustomizedDIDTx1, hash3)
	rawdb.WriteReceipts(db, hash3, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash3)

	////iWFAUYhTa35c1fPe3iCJvihZHx6quumnym is the owner controller of the credential
	verifableCredentialTx := getIDVerifiableCredentialTx(id1, "declare", custIDVerifCredDocBytes,
		privateKey1Str)
	data, err := json.Marshal(verifableCredentialTx)
	assert.NoError(t, err)
	err = checkDIDTransaction(data, statedb)
	assert.EqualError(t, err, "VerifiableCredential was revoked by owner")
}

// revoke again
func TestDuplicatedRevokeVerifiableCredentialTx(t *testing.T) {
	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	db := statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore)
	{
		id1 := "did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
		privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"
		hash1 := common.HexToHash("0x00234")
		statedb.Prepare(hash1, hash1, 1)
		tx1 := getPayloadDIDInfo(id1, "create", docDocBytes, privateKey1Str)
		buf := new(bytes.Buffer)
		tx1.Serialize(buf, did.DIDVersion)
		statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
		receipt := getCreateDIDReceipt(*tx1, hash1)
		rawdb.WriteReceipts(db, hash1, 0, types.Receipts{receipt}, 0)
		statedb.RemoveDIDLog(hash1)
	}

	id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	//	regisgter did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB
	hash2 := common.HexToHash("0x2345")
	statedb.Prepare(hash2, hash2, 1)
	tx2 := getPayloadDIDInfo(id2, "create", issuerDocByts, privateKey2Str)
	buf := new(bytes.Buffer)
	tx2.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id2, did.Create_DID_Operation, buf.Bytes())
	receipt := getCreateDIDReceipt(*tx2, hash2)
	rawdb.WriteReceipts(db, hash2, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash2)

	//id1 := "did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
	privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"
	verifableCredentialRevokeTx := getRevokeVerifiableCredentialTx("did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym#primary",
		"did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile", privateKey1Str)

	data, err := json.Marshal(verifableCredentialRevokeTx)

	assert.NoError(t, err)
	err = checkDIDTransaction(data, statedb)
	assert.NoError(t, err)

	buf = new(bytes.Buffer)
	hash := common.Hash{}
	statedb.Prepare(hash, hash, 1)
	verifableCredentialRevokeTx.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile", did.Revoke_Verifiable_Credential_Operation, buf.Bytes())
	receipt = getDeclareDIDReceipt(*verifableCredentialRevokeTx)
	rawdb.WriteReceipts(db, common.Hash{}, 0, types.Receipts{receipt}, 0)

	statedb.RemoveDIDLog(hash)

	verifableCredentialRevokeTx2 := getRevokeVerifiableCredentialTx("did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym#primary",
		"did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile", privateKey2Str)
	data, err = json.Marshal(verifableCredentialRevokeTx2)
	assert.NoError(t, err)
	err = checkDIDTransaction(data, statedb)
	assert.EqualError(t, err, "already have valid revoked")
}

//more than  one cotroller
func TestCustomizedDIDVerifiableCredentialTx2(t *testing.T) {
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	db := statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore)
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.BlockNumber = new(big.Int).SetInt64(1)
	evm.Time = new(big.Int).SetInt64(0)
	hash := common.Hash{}
	id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	tx0 := getPayloadDIDInfo(id2, "create", issuerDocByts, privateKey2Str)
	buff := new(bytes.Buffer)
	tx0.Serialize(buff, did.DIDVersion)
	statedb.AddDIDLog(id2, did.Create_DID_Operation, buff.Bytes())
	receipt := getCreateDIDReceipt(*tx0, hash)
	rawdb.WriteReceipts(db, hash, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash)

	hash1 := common.HexToHash("0x1234")
	statedb.Prepare(hash1, hash1, 1)
	idUser1 := "did:elastos:iXcRhYB38gMt1phi5JXJMjeXL2TL8cg58y"
	privateKeyUser1Str := "3z2QFDJE7woSUzL6az9sCB1jkZtzfvEZQtUnYVgQEebS"
	tx1 := getPayloadDIDInfo(idUser1, "create", user1IDDocByts, privateKeyUser1Str)
	buff = new(bytes.Buffer)
	tx1.Serialize(buff, did.DIDVersion)
	statedb.AddDIDLog(idUser1, did.Create_DID_Operation, buff.Bytes())
	receipt = getCreateDIDReceipt(*tx1, hash1)
	rawdb.WriteReceipts(db, hash1, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash1)

	hash2 := common.HexToHash("0x2345")
	statedb.Prepare(hash2, hash2, 1)
	privateKeyUser2Str := "AqBB8Uur4QwwBtFPeA2Yd5yF2Ni45gyz2osfFcMcuP7J"
	idUser2 := "did:elastos:idwuEMccSpsTH4ZqrhuHqg6y8XMVQAsY5g"
	tx2 := getPayloadDIDInfo(idUser2, "create", user2IDDocByts, privateKeyUser2Str)
	buff = new(bytes.Buffer)
	tx2.Serialize(buff, did.DIDVersion)
	statedb.AddDIDLog(idUser2, did.Create_DID_Operation, buff.Bytes())
	receipt = getCreateDIDReceipt(*tx2, hash2)
	rawdb.WriteReceipts(db, hash2, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash2)

	hash3 := common.HexToHash("0x3456")
	statedb.Prepare(hash3, hash3, 1)
	CustomizedDIDTx1 := getCustomizedDIDDocMultiSign(idUser1, idUser2, "create", fooBarIDDocBytes,
		privateKeyUser1Str, privateKeyUser2Str)
	customizedDID := "did:elastos:foobar"
	buff = new(bytes.Buffer)
	CustomizedDIDTx1.Serialize(buff, did.DIDVersion)
	statedb.AddDIDLog(customizedDID, did.Create_DID_Operation, buff.Bytes())
	receipt = getCreateDIDReceipt(*CustomizedDIDTx1, hash3)
	receipt.DIDLog.DID = customizedDID
	rawdb.WriteReceipts(db, hash3, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash3)

	verifableCredentialTx := getCustomizedDIDVerifiableCredPayloadContollers(idUser1, idUser2, "declare",
		custIDVerifyCredContrl, privateKeyUser1Str, privateKeyUser2Str)
	err := checkCredentialTX(evm, verifableCredentialTx)
	assert.NoError(t, err)
}

// more than one controllers
func getCustomizedDIDVerifiableCredPayloadContollers(id1, id2 string, didDIDPayload string, docBytes []byte,
	privateKeyStr1, privateKeyStr2 string) *did.DIDPayload {
	info := new(did.VerifiableCredentialDoc)
	json.Unmarshal(docBytes, info)
	fmt.Println("getCustomizedDIDDocMultiSign " + string(docBytes))

	//var Proofs []*types.Proof
	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     didDIDPayload,
		},
		Payload:       base64url.EncodeToString(docBytes),
		CredentialDoc: info,
	}
	proof1 := &did.Proof{
		Type:               "ECDSAsecp256r1",
		VerificationMethod: id1 + "#primary", //"did:elastos:" +
	}
	privateKey1 := base58.Decode(privateKeyStr1)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	proof1.Signature = base64url.EncodeToString(sign)
	//Proofs = append(Proofs, proof1)

	//proof2 := &types.Proof{
	//	Type:               "ECDSAsecp256r1",
	//	VerificationMethod: "did:elastos:" + id2 + "#primary",
	//}
	//privateKey2 := base58.Decode(privateKeyStr2)
	//sign2, _ := crypto.Sign(privateKey2, p.GetData())
	//proof2.Signature = base64url.EncodeToString(sign2)
	//Proofs = append(Proofs, proof2)

	p.Proof = *proof1
	return p
}

func getCustomizedDIDTx(id string, didDIDPayload string, docBytes []byte,
	privateKeyStr string) *did.DIDPayload {
	//pBytes := getDIDPayloadBytes(id)
	info := new(did.DIDDoc)
	json.Unmarshal(docBytes, info)

	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     didDIDPayload,
		},
		Payload: base64url.EncodeToString(docBytes),
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: "did:elastos:" + id + "#primary",
		},
		DIDDoc: info,
	}
	privateKey1 := base58.Decode(privateKeyStr)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}

func TestDeactivateCustomizedDIDTX(t *testing.T) {
	//id1 := "iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
	id1 := "did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"

	privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"
	tx1 := getPayloadDIDInfo(id1, "create", docDocBytes, privateKey1Str)

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	//evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})

	buf := new(bytes.Buffer)
	tx1.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
	receipt := getCreateDIDReceipt(*tx1, common.Hash{})
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 0, types.Receipts{receipt}, 0)

	statedb.RemoveDIDLog(common.Hash{})

	//id2 := "ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"

	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	tx2 := getPayloadDIDInfo(id2, "create", issuerDocByts, privateKey2Str)
	buf = new(bytes.Buffer)
	tx2.Serialize(buf, did.DIDVersion)

	hash1 := common.HexToHash("0x1234")
	statedb.Prepare(hash1, hash1, 1)
	statedb.AddDIDLog(id2, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*tx2, hash1)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), hash1, 0, types.Receipts{receipt}, 0)
	statedb.AddDIDLog(id2, did.Create_DID_Operation, buf.Bytes())

	statedb.RemoveDIDLog(hash1)

	CustomizedDIDTx1 := getCustomizedDIDTx(id1, "create", custIDSingleSignDocBytes1, privateKey1Str)
	customizedDID := "did:elastos:foobar"
	buf = new(bytes.Buffer)
	CustomizedDIDTx1.Serialize(buf, did.DIDVersion)
	hash2 := common.HexToHash("0x5678")
	statedb.Prepare(hash2, hash2, 1)
	statedb.AddDIDLog(customizedDID, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*CustomizedDIDTx1, hash2)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), hash2, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash2)
	//customizedDID
	//id1 is verificationmethod did
	//privateKey1Str outter proof sign(not for doc sign)
	txDeactivate := getDeactivateCustomizedDIDTx(customizedDID, id1, privateKey1Str)
	//Deactive did  have no
	data, err := json.Marshal(txDeactivate)
	assert.NoError(t, err)
	err = checkDIDTransaction(data, statedb)
	assert.NoError(t, err)
	statedb.RemoveDIDLog(hash2)

	hash3 := common.HexToHash("0x2345")
	buf = new(bytes.Buffer)
	txDeactivate.Serialize(buf, did.DIDVersion)
	statedb.Prepare(hash3, hash3, 1)
	statedb.AddDIDLog(customizedDID, did.Deactivate_DID_Operation, buf.Bytes())
	receipt = getDeactiveDIDReceipt(*txDeactivate)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), hash3, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash3)
	err = checkDIDTransaction(data, statedb)
	assert.EqualError(t, err, "DID WAS AREADY DEACTIVE")
}

//didDIDPayload must be create or update
func getDeactivateCustomizedDIDTx(customizedDID, verifiacationDID, privateKeyStr string) *did.DIDPayload {
	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     did.Deactivate_DID_Operation,
		},
		Payload: customizedDID,
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: verifiacationDID + "#primary", //"did:elastos:" +
		},
	}
	privateKey1 := base58.Decode(privateKeyStr)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)

	publickey := base58.Decode("2BhWFosWHCKtBQpsPD3QZUY4NwCzavKdZEh6HfQDhciAY")
	pubkey, err := elaCrypto.DecodePoint(publickey)
	fmt.Println(err)
	err = elaCrypto.Verify(*pubkey, p.GetData(), sign)
	fmt.Println(err)
	return p
}

func TestHeaderPayloadDIDTX(t *testing.T) {
	//this case payload is compact so ignore it
	return
	didParam.CustomIDFeeRate = 0
	err := checkDIDTransaction(headerPayloadBytes, nil)
	assert.NoError(t, err)
}

func checkDIDTransaction(didpayload []byte, db *state.StateDB) error {
	preData := common.Hash{}
	didpayload = append(preData.Bytes(), didpayload...)

	did_contract := new(operationDID)
	statedb := db
	if statedb == nil {
		statedb, _ = state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	}

	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
	evm.BlockNumber = new(big.Int).SetInt64(1)
	evm.chainConfig.CustomizeDIDHeight = big.NewInt(0)
	evm.chainConfig.DocArraySortHeight = new(big.Int).SetInt64(2)
	evm.chainConfig.MaxExpiredHeight = big.NewInt(100)
	evm.chainConfig.CustomizeDIDHeight = new(big.Int).SetInt64(0)
	evm.chainConfig.CheckCustomizeDIDBeginHeight = big.NewInt(0)

	evm.Context.Origin = common.HexToAddress("0xC445f9487bF570fF508eA9Ac320b59730e81e503")
	evm.chainConfig.OldDIDMigrateHeight = new(big.Int).SetInt64(2)
	evm.chainConfig.OldDIDMigrateAddr = "0xC445f9487bF570fF508eA9Ac320b59730e81e503"
	evm.chainConfig.MaxExpiredHeight = new(big.Int).SetInt64(100)

	evm.Time = &big.Int{}
	gas, _ := did_contract.RequiredGas(evm, []byte(didpayload))
	if gas == math.MaxUint64 {
		return errors.New("RequiredGas is 0")
	}
	result, err := did_contract.Run(evm, []byte(didpayload), gas)
	if err != nil {
		return err
	}
	val := common.BytesToHash(result)
	if val.Big().Uint64() != 1 {
		return errors.New("result error")
	}
	return nil
}

func checkDIDTransactionWithPayloadSyntax(didpayload []byte, db *state.StateDB) error {
	preData := common.Hash{}
	didpayload = append(preData.Bytes(), didpayload...)

	did_contract := new(operationDID)
	statedb := db
	if statedb == nil {
		statedb, _ = state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	}

	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
	evm.BlockNumber = new(big.Int).SetInt64(3)
	evm.chainConfig.DocArraySortHeight = new(big.Int).SetInt64(2)
	evm.chainConfig.CustomizeDIDHeight = new(big.Int).SetInt64(2)
	evm.chainConfig.CheckCustomizeDIDBeginHeight = big.NewInt(0)

	evm.Context.Origin = common.HexToAddress("0xB445f9487bF570fF508eA9Ac320b59730e81e503")
	evm.chainConfig.OldDIDMigrateHeight = new(big.Int).SetInt64(2)
	evm.chainConfig.OldDIDMigrateAddr = "0xC445f9487bF570fF508eA9Ac320b59730e81e503"
	evm.Time = &big.Int{}
	gas, _ := did_contract.RequiredGas(evm, []byte(didpayload))
	if gas == math.MaxUint64 {
		return errors.New("RequiredGas is 0")
	}
	result, err := did_contract.Run(evm, []byte(didpayload), gas)
	if err != nil {
		return err
	}
	val := common.BytesToHash(result)
	if val.Big().Uint64() != 1 {
		return errors.New("result error")
	}
	return nil
}

func checkDIDTransactionAfterMigrateHeight(didpayload []byte, db *state.StateDB) error {
	preData := common.Hash{}
	didpayload = append(preData.Bytes(), didpayload...)

	did_contract := new(operationDID)
	statedb := db
	if statedb == nil {
		statedb, _ = state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	}

	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
	evm.BlockNumber = new(big.Int).SetInt64(3)
	evm.Context.Origin = common.HexToAddress("0xC445f9487bF570fF508eA9Ac320b59730e81e503")
	evm.chainConfig.OldDIDMigrateHeight = new(big.Int).SetInt64(2)
	evm.chainConfig.OldDIDMigrateAddr = "0xb445f9487bF570fF508eA9Ac320b59730e81e503"
	evm.chainConfig.DocArraySortHeight = new(big.Int).SetInt64(2)
	evm.chainConfig.CustomizeDIDHeight = new(big.Int).SetInt64(2)
	evm.chainConfig.CheckCustomizeDIDBeginHeight = big.NewInt(0)

	evm.Time = &big.Int{}
	gas, _ := did_contract.RequiredGas(evm, []byte(didpayload))
	if gas == math.MaxUint64 {
		return errors.New("RequiredGas is 0")
	}
	result, err := did_contract.Run(evm, []byte(didpayload), gas)
	if err != nil {
		return err
	}
	val := common.BytesToHash(result)
	if val.Big().Uint64() != 1 {
		return errors.New("result error")
	}
	return nil
}

func getLenStr(len int) string {
	a := make([]byte, len)
	return string(a)
}

func TestGetLenthString(t *testing.T) {
	strLen := 0
	str := getLenStr(strLen)
	assert.Equal(t, strLen, len(str))

	strLen = 1
	str = getLenStr(strLen)
	assert.Equal(t, strLen, len(str))

	strLen = 2
	str = getLenStr(strLen)
	assert.Equal(t, strLen, len(str))

	strLen = 100
	str = getLenStr(strLen)
	assert.Equal(t, strLen, len(str))
}

//test completely
func TestGetCustomizedDIDLenFactor(t *testing.T) {
	tests := []struct {
		ID     string
		factor float64
	}{
		{getLenStr(0), 0.3},
		{getLenStr(1), 6400},
		{getLenStr(2), 3200},
		{getLenStr(3), 1200},
		{getLenStr(4), 100},
		{getLenStr(9), 99},
		{getLenStr(32), 97},
		{getLenStr(33), 97},
		{getLenStr(64), 100},
		{getLenStr(65), 300},
		{getLenStr(255), 9800},
	}
	for _, test := range tests {
		lenFactor := getCustomizedDIDLenFactor(test.ID)
		assert.Equal(t, test.factor, lenFactor)
	}
}

func TestGetValidPeriodFactor(t *testing.T) {
	tests := []struct {
		Expires  string
		lifeRate float64
	}{
		//Days: 1, rate: 0.4958904109589041
		{"2021-03-18T09:53:35Z", 0.4958904109589041},
		//Days: 10, rate: 0.5205479452054794
		{"2021-03-27T09:53:35Z", 0.5205479452054794},
		//Days: 30, rate: 0.5753424657534246
		{"2021-04-16T09:53:35Z", 0.5753424657534246},
		//Months:   2, rate: 0.6575342465753424
		{"2021-05-16T17:00:00Z", 0.6575342465753424},
		//Months:   3, rate: 0.7397260273972602
		{"2021-06-15T17:00:00Z", 0.7397260273972602},
		//Years:   1, rate: 1.0
		{"2022-03-17T09:53:35Z", 1.0},
		//Years:  19, rate: 16.578681317337157
		{"2040-03-12T09:53:35Z", 16.578681317337157},
	}
	//1615946015 2021 3-17 09:53:35
	for _, test := range tests {
		lenFactor := getValidPeriodFactor(test.Expires, time.Unix(1615946015, 0))
		assert.Equal(t, test.lifeRate, lenFactor)
	}
}

//test completely
func TestGetOperationFactor(t *testing.T) {
	tests := []struct {
		Operation string
		factor    float64
	}{
		{"create", 1},
		{"update", 0.8},
		{"transfer", 1.2},
		{"deactivate", 0.3},
		{"declare", 1},
		{"revoke", 0.3},
		{"default_other", 1},
	}
	for _, test := range tests {
		lenFactor := getOperationFactor(test.Operation)
		assert.Equal(t, test.factor, lenFactor)
	}
}

//test completely
func TestGetControllerFactor(t *testing.T) {
	names := []string{"controller1", "controller2"}
	controller := make([]interface{}, len(names))
	for i, v := range names {
		controller[i] = v
	}
	str := "controller"
	tests := []struct {
		controller interface{}
		factor     float64
	}{
		{nil, 0},
		{controller, 32},
		{str, 1},
	}
	for _, test := range tests {
		lenFactor := getControllerFactor(test.controller)
		assert.Equal(t, test.factor, lenFactor)
	}
}

//test completely
func TestGetSizeFactor(t *testing.T) {
	tests := []struct {
		payLoadSize int
		factor      float64
	}{
		{1000, 1},
		{1 * 1024, 1},
		{2 * 1024, 1.1505149978319906},
		{32 * 1024, 1.7525749891599531},
		{33 * 1024, 1.924931548775831},
		{34 * 1024, 3.1967102737178337},
		{4142, 1.303455068958811},
		{1024 * 1024, 1507.8735777995842},
		{32771, 0.6613621736996009},
	}
	for _, test := range tests {
		lenFactor := getSizeFactor(test.payLoadSize)
		assert.Equal(t, test.factor, lenFactor)
	}
}

func TestCreateMyOwnSign(t *testing.T) {
	//return
	ticket := new(did.CustomIDTicket)
	json.Unmarshal(batTTDocByts, ticket)
	fmt.Println("ticket", ticket)
	ticket.TransactionID = "5636c8eea0734a7013d71b58e597135f637bf6d193677cb7f56a1d36e3b723cc"

	dest, err := os.Create("test11.json")
	if err != nil {
		return
	}
	defer dest.Close()
	CustomizedDIDProof := &did.TicketProof{}
	if err := Unmarshal(ticket.Proof, CustomizedDIDProof); err != nil {
		return
	}
	privateKeyStr1 := "AqBB8Uur4QwwBtFPeA2Yd5yF2Ni45gyz2osfFcMcuP7J"
	privateKey1 := base58.Decode(privateKeyStr1)
	sign, _ := elaCrypto.Sign(privateKey1, ticket.GetData())
	CustomizedDIDProof.Signature = base64url.EncodeToString(sign)
	ticket.Proof = CustomizedDIDProof

	b11, err := json.Marshal(ticket)
	if err != nil {
		fmt.Println("error:", err)
	}
	dest.Write(b11)
	os.Remove("test11.json")
}

func TestCustomizedDIDTransferSingleProof(t *testing.T) {
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.BlockNumber = new(big.Int).SetInt64(1)
	evm.chainConfig.DocArraySortHeight = new(big.Int).SetInt64(2)
	evm.chainConfig.MaxExpiredHeight = new(big.Int).SetInt64(100)
	evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))

	user1 := "did:elastos:iXcRhYB38gMt1phi5JXJMjeXL2TL8cg58y"
	user1PrivateKeyStr := "413uivqLEMjPd8bo42K9ic6VXpgYcJLEwB3vefxJDhXJ"
	user1TX := getPayloadDIDInfo(user1, "create", user1IDDocByts, user1PrivateKeyStr)
	buf := new(bytes.Buffer)
	user1TX.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(user1TX.DIDDoc.ID, did.Create_DID_Operation, buf.Bytes())
	receipt := getCreateDIDReceipt(*user1TX, common.Hash{})
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(common.Hash{})

	hash1 := common.HexToHash("0x1234")
	statedb.Prepare(hash1, hash1, 1)
	user2 := "did:elastos:idwuEMccSpsTH4ZqrhuHqg6y8XMVQAsY5g"
	user2PrivateKeyStr := "AqBB8Uur4QwwBtFPeA2Yd5yF2Ni45gyz2osfFcMcuP7J"
	user2TX := getPayloadDIDInfo(user2, "create", user2IDDocByts, user2PrivateKeyStr)
	buf = new(bytes.Buffer)
	user2TX.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(user1TX.DIDDoc.ID, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*user2TX, hash1)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), hash1, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash1)

	hash2 := common.HexToHash("0x2345")
	statedb.Prepare(hash2, hash2, 1)
	user3 := "did:elastos:igXiyCJEUjGJV1DMsMa4EbWunQqVg97GcS"
	user3PrivateKeyStr := "413uivqLEMjPd8bo42K9ic6VXpgYcJLEwB3vefxJDhXJ"
	user3TX := getPayloadDIDInfo(user3, "create", user3IDDocByts, user3PrivateKeyStr)
	buf = new(bytes.Buffer)
	user3TX.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(user1TX.DIDDoc.ID, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*user3TX, hash2)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), hash2, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash2)

	hash3 := common.HexToHash("0x3456")
	statedb.Prepare(hash3, hash3, 1)
	user4 := "did:elastos:igHbSCez6H3gTuVPzwNZRrdj92GCJ6hD5d"
	//4YWYVhUNF1LLpR5rQeJUg23ESMdAGx6zqwUdcNkV5Rq
	//EouptA61qGJPz5mjt2JVduv5XapDR7nhJuBKqntDpkEU
	user4PrivateKeyStr := "EouptA61qGJPz5mjt2JVduv5XapDR7nhJuBKqntDpkEU"
	user4TX := getPayloadDIDInfo(user4, "create", user4IDDocByts, user4PrivateKeyStr)
	buf = new(bytes.Buffer)
	user4TX.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(user4TX.DIDDoc.ID, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*user4TX, hash3)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), hash3, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash3)

	hash4 := common.HexToHash("e71e0aee28c8119c4e8069fb9faa22c0")
	statedb.Prepare(hash4, hash4, 1)
	bazPrivateKeyStr := "413uivqLEMjPd8bo42K9ic6VXpgYcJLEwB3vefxJDhXJ"
	CustomizedDIDTx1 := getCustomizedDIDTx("did:elastos:baz", "create", barzIDDocByts, bazPrivateKeyStr)
	//customizedDID := "did:elastos:baz"
	buf = new(bytes.Buffer)
	CustomizedDIDTx1.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(CustomizedDIDTx1.DIDDoc.ID, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*CustomizedDIDTx1, hash4)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), hash4, 0, types.Receipts{receipt}, 0)
	//CustomizedDIDTx1
	statedb.RemoveDIDLog(hash4)

	//doc baz.new.id.json
	//transfer baz.tt.json
	txhash := hash4.String()[2:]
	transferTx := getCustomizedDIDTransferTx(user4, "transfer", bazNewIDDocByts, batTTDocByts, user4PrivateKeyStr, user2PrivateKeyStr, txhash)

	didParam.CustomIDFeeRate = 0
	didParam.IsTest = true

	data, err := json.Marshal(transferTx)
	assert.NoError(t, err)
	transferErr := checkDIDTransaction(data, statedb)
	assert.NoError(t, transferErr)
	didParam.IsTest = false
}

func getCustomizedDIDTransferTx(id string, operation string, docBytes []byte, ticketBytes []byte,
	payloadPrivateKeyStr, ticketPrivateKeyStr, lastTxStr string) *did.DIDPayload {
	info := new(did.DIDDoc)
	json.Unmarshal(docBytes, info)

	ticket := new(did.CustomIDTicket)
	json.Unmarshal(ticketBytes, ticket)
	fmt.Println("ticket.GetData()", ticket.GetData())

	ticket.TransactionID = lastTxStr
	CustomizedDIDProof := &did.TicketProof{}
	if err := Unmarshal(ticket.Proof, CustomizedDIDProof); err != nil {
		return nil
	}

	ticketPrivateKey := base58.Decode(ticketPrivateKeyStr)
	sign, _ := elaCrypto.Sign(ticketPrivateKey, ticket.CustomIDTicketData.GetData())
	CustomizedDIDProof.Signature = base64url.EncodeToString(sign)
	ticket.Proof = CustomizedDIDProof
	fmt.Println("after sign ticket.GetData()", ticket.GetData())

	data, err := json.Marshal(ticket)
	if err != nil {
		fmt.Println("Marshal err", data)
	}

	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     operation,
			PreviousTxid:  lastTxStr,
			Ticket:        base64url.EncodeToString(data),
		},
		Payload: base64url.EncodeToString(docBytes),
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: id + "#primary", //"did:elastos:" +
		},
		DIDDoc: info,
		Ticket: ticket,
	}
	privateKey1 := base58.Decode(payloadPrivateKeyStr)
	signTicket, _ := elaCrypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(signTicket)
	return p
}

func getMultiContrCustomizedDIDTransferTx(id string, operation string, docBytes []byte, ticketBytes []byte,
	privateKeyStr, user1PrivateKeyStr, user3PrivateKeyStr, lastTxStr string) *did.DIDPayload {

	info := new(did.DIDDoc)
	json.Unmarshal(docBytes, info)

	ticket := new(did.CustomIDTicket)
	json.Unmarshal(ticketBytes, ticket)
	ticket.TransactionID = lastTxStr
	user1 := "did:elastos:iXcRhYB38gMt1phi5JXJMjeXL2TL8cg58y"
	var ticketPrivateKey []byte
	DIDProofArray := make([]*did.TicketProof, 0)
	if err := Unmarshal(ticket.Proof, &DIDProofArray); err == nil {
		for _, CustomizedDIDProof := range DIDProofArray {
			if strings.HasPrefix(CustomizedDIDProof.VerificationMethod, user1) {
				ticketPrivateKey = base58.Decode(user1PrivateKeyStr)
			} else {
				ticketPrivateKey = base58.Decode(user3PrivateKeyStr)
			}
			sign, _ := elaCrypto.Sign(ticketPrivateKey, ticket.CustomIDTicketData.GetData())
			CustomizedDIDProof.Signature = base64url.EncodeToString(sign)
		}
	}
	ticket.Proof = DIDProofArray

	data, err := json.Marshal(ticket)
	if err != nil {
		fmt.Println("Marshal err", data)
	}

	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     operation,
			PreviousTxid:  lastTxStr,
			Ticket:        base64url.EncodeToString(data),
		},
		Payload: base64url.EncodeToString(docBytes),
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: id + "#primary", //"did:elastos:" +
		},
		DIDDoc: info,
		Ticket: ticket,
	}
	privateKey1 := base58.Decode(privateKeyStr)
	signTicket, _ := elaCrypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(signTicket)
	return p
}

func GetprivateKeyStr(privateKey1Str string) string {
	privateKeyTemp := base58.Decode(privateKey1Str)
	privateKey := privateKeyTemp[46:78]
	base58PrivageKey := base58.Encode(privateKey)
	return base58PrivageKey
}

func TestCustomizedDIDTransferProofs(t *testing.T) {
	hash1 := common.Hash{}
	statedb, _ := state.New(hash1, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
	evm.Time = big.NewInt(0)
	evm.BlockNumber = new(big.Int).SetInt64(1)
	evm.chainConfig.DocArraySortHeight = new(big.Int).SetInt64(2)
	evm.chainConfig.CustomizeDIDHeight = big.NewInt(3000000)
	evm.chainConfig.CheckCustomizeDIDBeginHeight = big.NewInt(0)

	evm.chainConfig.MaxExpiredHeight = big.NewInt(100)

	user1 := "did:elastos:iXcRhYB38gMt1phi5JXJMjeXL2TL8cg58y"
	user1PrivateKeyStr := "3z2QFDJE7woSUzL6az9sCB1jkZtzfvEZQtUnYVgQEebS"
	user1TX := getPayloadDIDInfo(user1, "create", user1IDDocByts, user1PrivateKeyStr)
	//customizedDID := "did:elastos:baz"
	buf := new(bytes.Buffer)
	user1TX.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(user1TX.DIDDoc.ID, did.Create_DID_Operation, buf.Bytes())
	receipt := getCreateDIDReceipt(*user1TX, hash1)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), hash1, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash1)

	hash2 := common.HexToHash("0x1234")
	statedb.Prepare(hash2, hash2, 1)
	user2 := "did:elastos:idwuEMccSpsTH4ZqrhuHqg6y8XMVQAsY5g"
	user2PrivateKeyStr := "413uivqLEMjPd8bo42K9ic6VXpgYcJLEwB3vefxJDhXJ"
	user2TX := getPayloadDIDInfo(user2, "create", user2IDDocByts, user2PrivateKeyStr)
	buf = new(bytes.Buffer)
	user2TX.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(user2TX.DIDDoc.ID, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*user2TX, hash2)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), hash2, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash2)

	hash3 := common.HexToHash("0x2345")
	statedb.Prepare(hash3, hash3, 1)
	user3 := "did:elastos:igXiyCJEUjGJV1DMsMa4EbWunQqVg97GcS"
	user3PrivateKeyStr := "BdQX3FcigWjRURJ3idTQ3A2vry4e1RwSg2MtfE5zePDy"
	user3TX := getPayloadDIDInfo(user3, "create", user3IDDocByts, user3PrivateKeyStr)
	buf = new(bytes.Buffer)
	user3TX.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(user3TX.DIDDoc.ID, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*user3TX, hash3)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), hash3, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash3)

	hash4 := common.HexToHash("0x3456")
	statedb.Prepare(hash4, hash4, 1)
	user4 := "did:elastos:igHbSCez6H3gTuVPzwNZRrdj92GCJ6hD5d"
	//4YWYVhUNF1LLpR5rQeJUg23ESMdAGx6zqwUdcNkV5Rq
	//EouptA61qGJPz5mjt2JVduv5XapDR7nhJuBKqntDpkEU
	user4PrivateKeyStr := "EouptA61qGJPz5mjt2JVduv5XapDR7nhJuBKqntDpkEU"
	user4TX := getPayloadDIDInfo(user4, "create", user4IDDocByts, user4PrivateKeyStr)
	buf = new(bytes.Buffer)
	user4TX.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(user4TX.DIDDoc.ID, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*user4TX, hash4)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), hash4, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash4)

	hash5 := common.HexToHash("0x4567")
	statedb.Prepare(hash5, hash5, 1)
	bazPrivateKeyStr := "413uivqLEMjPd8bo42K9ic6VXpgYcJLEwB3vefxJDhXJ"
	CustomizedDIDTx1 := getCustomizedDIDTx("did:elastos:foobar", "create", fooBarIDDocBytes, bazPrivateKeyStr)
	//customizedDID := "did:elastos:foobar"
	buf = new(bytes.Buffer)
	CustomizedDIDTx1.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(CustomizedDIDTx1.DIDDoc.ID, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*CustomizedDIDTx1, hash5)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), hash5, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash5)

	txhash := hash5.String()[2:]
	//getMultiContrCustomizedDIDTransferTx getMulContrCustomizedDIDTransferDoc
	transferTx := getMultiContrCustomizedDIDTransferTx(user4, "transfer", fooBarNewIDDocBytes, fooBarTTIDDocBytes,
		user4PrivateKeyStr, user1PrivateKeyStr, user3PrivateKeyStr, txhash)
	didParam.CustomIDFeeRate = 0
	didParam.IsTest = true
	transferErr := checkCustomizedDID(evm, transferTx, 0)
	assert.NoError(t, transferErr)
	didParam.IsTest = false
}

func TestGetprivateKeyStr(t *testing.T) {
	//imUUPBfrZ1yZx6nWXe6LNN59VeX2E6PPKj
	privateKey1Str := "xprvA39XqfTw2FPEfpMJmM6jK1gzzRv8p1GYJS3DUEEbp1SibLrRyZzHijYTTvzy2a57Es8CBxs2xseMNoLC7nNGxsJY3nfCT3aUeozRQoy8vTH"
	base58PrivageKey := GetprivateKeyStr(privateKey1Str)
	fmt.Println("base58PrivageKey ", base58PrivageKey)
	assert.Equal(t, "413uivqLEMjPd8bo42K9ic6VXpgYcJLEwB3vefxJDhXJ", base58PrivageKey)

	//"did:elastos:igHbSCez6H3gTuVPzwNZRrdj92GCJ6hD5d"
	base58PrivageKey2 := GetprivateKeyStr("xprvA39XqfTw2FPEqBoXJv95kX4KUSjwajnD99fw8pMFv7R71SN8RkJQ1idgV5MR2oLyW1JJUi7sjXYRTDjmHqbkqmCNYbJpapiTnin5N5aj7UV")
	fmt.Println("base58PrivageKey2 ", base58PrivageKey2)
	assert.Equal(t, "EouptA61qGJPz5mjt2JVduv5XapDR7nhJuBKqntDpkEU", base58PrivageKey2)

	//did:elastos:idwuEMccSpsTH4ZqrhuHqg6y8XMVQAsY5g
	base58PrivageKey3 := GetprivateKeyStr("xprvA39XqfTw2FPEnHs4A7H9DRDxxGn7dJpyTdxHqUmBthNFhPAJGATFNdL8wBFZ1NHkC6USNWyEchycKkD3RoT7tPSfugBQVyyPNH3mrEP8KUy")
	fmt.Println("base58PrivageKey3 ", base58PrivageKey3)
	assert.Equal(t, "AqBB8Uur4QwwBtFPeA2Yd5yF2Ni45gyz2osfFcMcuP7J", base58PrivageKey3)

	//iXcRhYB38gMt1phi5JXJMjeXL2TL8cg58y
	//xprvA39XqfTw2FPEjJK4n4XkDomsf2wnTD4n6nZgSm34Da9MosYtFNStyTGRpZU5aRyxpfJ98oK8Yw5GuBnP1Bx7oCrZB9BhWXR28orHW6A5QRn
	base58PrivageKey4 := GetprivateKeyStr("xprvA39XqfTw2FPEjJK4n4XkDomsf2wnTD4n6nZgSm34Da9MosYtFNStyTGRpZU5aRyxpfJ98oK8Yw5GuBnP1Bx7oCrZB9BhWXR28orHW6A5QRn")
	fmt.Println("base58PrivageKey4 ", base58PrivageKey4)
	assert.Equal(t, "3z2QFDJE7woSUzL6az9sCB1jkZtzfvEZQtUnYVgQEebS", base58PrivageKey4)

	//igXiyCJEUjGJV1DMsMa4EbWunQqVg97GcS
	//xprvA39XqfTw2FPEneKSjzk2xrKda9547StuuJ3MTHiQL2uczmabXnP9S8xtUbmsLdBPAA558ekswKjxinqx199TvtArQ2GvJyA4u8uisCmKG62

	base58PrivageKey5 := GetprivateKeyStr("xprvA39XqfTw2FPEneKSjzk2xrKda9547StuuJ3MTHiQL2uczmabXnP9S8xtUbmsLdBPAA558ekswKjxinqx199TvtArQ2GvJyA4u8uisCmKG62")
	fmt.Println("base58PrivageKey5 ", base58PrivageKey5)
	assert.Equal(t, "BdQX3FcigWjRURJ3idTQ3A2vry4e1RwSg2MtfE5zePDy", base58PrivageKey5)
}

func TestCheckKeyReference(t *testing.T) {
	var didPayloadBytes = []byte(
		`{
        "id" : "did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j",
        "publicKey":[{ "id": "did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j#default",
                       "type":"ECDSAsecp256r1",
                       "controller":"did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j",
                       "publicKeyBase58":"zxt6NyoorFUFMXA8mDBULjnuH3v6iNdZm42PyG4c1YdC"
                      },
					{
					   "id": "did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j#master",
					   "type":"ECDSAsecp256r1",
					   "controller":"",
					   "publicKeyBase58":"zNxoZaZLdackZQNMas7sCkPRHZsJ3BtdjEvM2y5gNvKJ"
				   },
					{
					   "id": "did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j#otherController",
					   "type":"ECDSAsecp256r1",
					   "controller":"did:elastos:idwuEMccSpsTH4ZqrhuHqg6y8XMVQAsY5g",
					   "publicKeyBase58":"zNxoZaZLdackZQNMas7sCkPRHZsJ3BtdjEvM2y5gNvKJ"
				   }
                    ],
        "authentication":["did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j#default",
                          "#master",
                          "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default",
                          {
                               "id": "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default",
                               "type":"ECDSAsecp256r1",
                               "controller":"did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j",
                               "publicKeyBase58":"zNxoZaZLdackZQNMas7sCkPRHZsJ3BtdjEvM2y5gNvKJ"
                           }
                         ],
        "authorization":["did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j#default",
						"#master",
						 "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default",
							{
                               "id": "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default",
                               "type":"ECDSAsecp256r1",
                               "controller":"did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j",
                               "publicKeyBase58":"zNxoZaZLdackZQNMas7sCkPRHZsJ3BtdjEvM2y5gNvKJ"
                           }
						],
        "expires" : "2023-02-10T17:00:00Z"
	}`)
	info := new(did.DIDDoc)
	json.Unmarshal(didPayloadBytes, info)
	fmt.Println("123")
	id := "did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j"

	err := checkKeyReference(id, info.Authentication, info.Authorization, info.PublicKey)
	assert.NoError(t, err)
	//						"#notexist",
	oriAuth := info.Authentication
	//oriAuthor := info.Authorization
	info.Authentication = append(info.Authentication, "#notexist")
	err = checkKeyReference(id, info.Authentication, info.Authorization, info.PublicKey)
	assert.Equal(t, "checkKeyReference authen key is not exit in public key array", err.Error())
	info.Authentication = oriAuth
	info.Authorization = append(info.Authorization, "#notexist")
	err = checkKeyReference(id, info.Authentication, info.Authorization, info.PublicKey)
	assert.Equal(t, "checkKeyReference authorization key is not exit in public key array", err.Error())
}

func TestIsDID(t *testing.T) {
	//default key controller is not iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j
	var didPayloadBytes = []byte(
		`{
        "id" : "did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j",
        "publicKey":[{ "id": "did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j#default",
                       "type":"ECDSAsecp256r1",
                       "controller":"did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN",
                       "publicKeyBase58":"zxt6NyoorFUFMXA8mDBULjnuH3v6iNdZm42PyG4c1YdC"
                      },
					{
					   "id": "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#master",
					   "type":"ECDSAsecp256r1",
					   "controller":"did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN",
					   "publicKeyBase58":"zNxoZaZLdackZQNMas7sCkPRHZsJ3BtdjEvM2y5gNvKJ"
				   }
                    ],
        "authentication":["did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j#default",
                          {
                               "id": "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default",
                               "type":"ECDSAsecp256r1",
                               "controller":"did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN",
                               "publicKeyBase58":"zNxoZaZLdackZQNMas7sCkPRHZsJ3BtdjEvM2y5gNvKJ"
                           }
                         ],
        "authorization":["did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default"],
        "expires" : "2023-02-10T17:00:00Z"
	}`)
	info := new(did.DIDDoc)
	json.Unmarshal(didPayloadBytes, info)

	isDID := isRegistDID(info)
	assert.Equal(t, false, isDID)
}

func TestDocSliceSort(t *testing.T) {
	{
		id1 := "did:elastos:iYm2nAMXetnhtQYzF4nAa8dDKhfnxYqNDQ"
		privateKey1Str := "413uivqLEMjPd8bo42K9ic6VXpgYcJLEwB3vefxJDhXJ"
		tx1 := getPayloadDIDInfo(id1, "create", jianbinCtrl5PubKeyTest, privateKey1Str)

		outputPayloadToFile(tx1, "user2.dest.payload.json")
		statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
		evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
		evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
		evm.Time = big.NewInt(0)
		evm.BlockNumber = new(big.Int).SetInt64(1)
		evm.chainConfig.DocArraySortHeight = new(big.Int).SetInt64(2)
		evm.chainConfig.CustomizeDIDHeight = big.NewInt(3000000)
		evm.chainConfig.CheckCustomizeDIDBeginHeight = big.NewInt(0)

		evm.chainConfig.MaxExpiredHeight = big.NewInt(100)

		buf := new(bytes.Buffer)
		tx1.Serialize(buf, did.DIDVersion)

		statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
		err1 := rawdb.PersistRegisterDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(common.Hash{}), 0, 100)
		assert.NoError(t, err1)
		statedb.RemoveDIDLog(common.Hash{})
	}
	didParam.IsTest = true
	err := checkDIDTransactionAfterMigrateHeight(changeDocPayload, nil)
	assert.NoError(t, err)

}

//new
func TestNewCustomizedDID(t *testing.T) {
	id1 := "did:elastos:imUUPBfrZ1yZx6nWXe6LNN59VeX2E6PPKj"
	privateKey1Str := "413uivqLEMjPd8bo42K9ic6VXpgYcJLEwB3vefxJDhXJ" //413uivqLEMjPd8bo42K9ic6VXpgYcJLEwB3vefxJDhXJ
	tx1 := getPayloadDIDInfo(id1, "create", id11DocByts, privateKey1Str)

	outputPayloadToFile(tx1, "user2.dest.payload.json")
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
	evm.Time = big.NewInt(0)
	evm.BlockNumber = new(big.Int).SetInt64(1)
	evm.chainConfig.DocArraySortHeight = new(big.Int).SetInt64(2)
	evm.chainConfig.CustomizeDIDHeight = big.NewInt(3000000)
	evm.chainConfig.CheckCustomizeDIDBeginHeight = big.NewInt(0)

	evm.chainConfig.MaxExpiredHeight = big.NewInt(100)

	buf := new(bytes.Buffer)
	tx1.Serialize(buf, did.DIDVersion)

	//examplercorp.id.json
	didParam.IsTest = true
	tx3 := getCustomizedDIDDoc(id1, "create", customizedDIDDocSingleContrller, privateKey1Str)
	//did:elastos:example
	fileName := "did:elastos:example.json"
	outputPayloadToFile(tx3, fileName)

	receipt := getCreateDIDReceipt(*tx1, common.Hash{})
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 0, types.Receipts{receipt}, 0)

	didParam.CustomIDFeeRate = 0
	err3 := checkCustomizedDID(evm, tx3, 20000)
	assert.NoError(t, err3)

	didParam.IsTest = false
	os.Remove(fileName)
	os.Remove("user2.dest.payload.json")

}

func TestDIDPublicKeyUse(t *testing.T) {

	//payload use default key #primary
	{
		id1 := "did:elastos:iqKXrBRrv1vqnaCiHy2kP1LDcmDZmG6hEy"
		privateKey1Str := "3zEQ9H14Edkm7nRqeCopS7xT8ccsSh9pMxdyW4LnYdRv"
		tx1 := getPayloadDIDInfoWithPayloadURI(id1, "create", didDocPubKeyTest, privateKey1Str, "#primary")
		statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))

		docBytes, err := json.Marshal(tx1)
		assert.NoError(t, err)
		err = checkDIDTransactionWithPayloadSyntax(docBytes, statedb)
		assert.NoError(t, err)
	}
	//payload use authen key #key2
	{
		id1 := "did:elastos:iqKXrBRrv1vqnaCiHy2kP1LDcmDZmG6hEy"
		privateKey2Str := "FPHbdqtMZ6j4isEgbn54eKUjFSd84ffbBk7GMadDhiJF"
		tx1 := getPayloadDIDInfoWithPayloadURI(id1, "create", didDocPubKeyTest, privateKey2Str, "#key2")
		statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))

		docBytes, err := json.Marshal(tx1)
		assert.NoError(t, err)
		err = checkDIDTransaction(docBytes, statedb)
		assert.NoError(t, err)
	}
	//test controller1
	{
		id1 := "did:elastos:ijb8oNP3ZMKP6N5swJCoiYtoUbomAK13Xy"
		privateKey2Str := "78cQWUwaqVHnn7JLE7xNjmDcEYyU4fnMuq6jPTUYsdi"
		tx1 := getPayloadDIDInfoWithPayloadURI(id1, "create", jianbinCtrl1PubKeyTest, privateKey2Str, "#primary")
		statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))

		docBytes, err := json.Marshal(tx1)
		assert.NoError(t, err)
		err = checkDIDTransaction(docBytes, statedb)
		assert.NoError(t, err)
	}
	//test controller2
	{
		id1 := "did:elastos:iidhLBRtSLMzsAuK3uHveLccTfZtCwRreh"
		privateKey2Str := "4fDnYELy1um12fQPA7V6U953tdMwoUVTsAM5Lp5RF1AU"
		tx1 := getPayloadDIDInfoWithPayloadURI(id1, "create", jianbinCtrl2PubKeyTest, privateKey2Str, "#primary")
		statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))

		docBytes, err := json.Marshal(tx1)
		assert.NoError(t, err)
		err = checkDIDTransaction(docBytes, statedb)
		assert.NoError(t, err)
	}
	//test controller3
	{
		id1 := "did:elastos:ibTPLrp758SGtLCzLoiF4VQqCpT7cNCAdh"
		privateKey2Str := "BreRiS8SegmJ9pRaxPrLEZvrtiqtdAg7ghqyDQyQ3tun"
		tx1 := getPayloadDIDInfoWithPayloadURI(id1, "create", jianbinCtrl3PubKeyTest, privateKey2Str, "#primary")
		statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))

		docBytes, err := json.Marshal(tx1)
		assert.NoError(t, err)
		err = checkDIDTransaction(docBytes, statedb)
		assert.NoError(t, err)
	}
}

func TestCustomizeDIDSingleCtrlPublicKeyUse(t *testing.T) {
	id1 := "did:elastos:iqKXrBRrv1vqnaCiHy2kP1LDcmDZmG6hEy"
	privateKey1Str := "3zEQ9H14Edkm7nRqeCopS7xT8ccsSh9pMxdyW4LnYdRv"
	tx1 := getPayloadDIDInfoWithPayloadURI(id1, "create", didDocPubKeyTest, privateKey1Str, "#primary")
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
	evm.Time = big.NewInt(0)
	evm.BlockNumber = new(big.Int).SetInt64(1)
	evm.chainConfig.DocArraySortHeight = new(big.Int).SetInt64(2)

	buf := new(bytes.Buffer)
	tx1.Serialize(buf, did.DIDVersion)

	statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
	statedb.RemoveDIDLog(common.Hash{})
	receipt := getCreateDIDReceipt(*tx1, common.Hash{})
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 0, types.Receipts{receipt}, 0)
	didParam.IsTest = true
	didParam.CustomIDFeeRate = 0

	//payload use controller default key #primary
	{
		tx2 := getPayloadDIDInfoWithPayloadURI(id1, "create", custmizeDIDSingleCtrlTest, privateKey1Str, "#primary")
		docBytes, err := json.Marshal(tx2)
		assert.NoError(t, err)
		err = checkDIDTransactionWithPayloadSyntax(docBytes, statedb)
		assert.NoError(t, err)
	}
	//payload use controller authen key #key2
	{
		privateKey2Str := "FPHbdqtMZ6j4isEgbn54eKUjFSd84ffbBk7GMadDhiJF"
		tx2 := getPayloadDIDInfoWithPayloadURI(id1, "create", custmizeDIDSingleCtrlTest, privateKey2Str, "#key2")
		docBytes, err := json.Marshal(tx2)
		assert.NoError(t, err)
		err = checkDIDTransactionWithPayloadSyntax(docBytes, statedb)
		assert.NoError(t, err)
	}
	//payload use customizdid Lindalittlefish02 authen key #append
	{

		privateKeyappendStr := "6PjyiCxx71fMF5WvercSRoDySDTHWZXsTLGPYYZsYmfX"
		tx2 := getPayloadDIDInfoWithPayloadURI("did:elastos:Lindalittlefish02", "create", custmizeDIDSingleCtrlTest, privateKeyappendStr, "#append")
		docBytes, err := json.Marshal(tx2)
		assert.NoError(t, err)
		err = checkDIDTransactionWithPayloadSyntax(docBytes, statedb)
		assert.NoError(t, err)
	}
}

func TestCustomizeDIDMultiCtrlPublicKeyUse(t *testing.T) {

	didParam.IsTest = true
	defer func() {
		didParam.IsTest = false
	}()
	idUser1 := "did:elastos:ijb8oNP3ZMKP6N5swJCoiYtoUbomAK13Xy"
	privateKeyUser1Str := "78cQWUwaqVHnn7JLE7xNjmDcEYyU4fnMuq6jPTUYsdi"
	tx1 := getPayloadDIDInfo(idUser1, "create", jianbinCtrl1PubKeyTest, privateKeyUser1Str)
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
	evm.Time = big.NewInt(0)
	evm.BlockNumber = new(big.Int).SetInt64(3)
	evm.chainConfig.CustomizeDIDHeight = new(big.Int).SetInt64(3)
	evm.chainConfig.CheckCustomizeDIDBeginHeight = big.NewInt(0)
	evm.chainConfig.DocArraySortHeight = new(big.Int).SetInt64(2)
	buf := new(bytes.Buffer)
	tx1.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(idUser1, did.Create_DID_Operation, buf.Bytes())
	receipt := getCreateDIDReceipt(*tx1, common.Hash{})
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(common.Hash{})

	privateKeyUser2Str := "4fDnYELy1um12fQPA7V6U953tdMwoUVTsAM5Lp5RF1AU"
	idUser2 := "did:elastos:iidhLBRtSLMzsAuK3uHveLccTfZtCwRreh"
	tx2 := getPayloadDIDInfo(idUser2, "create", jianbinCtrl2PubKeyTest, privateKeyUser2Str)
	hash1 := common.HexToHash("0x1234")
	buf = new(bytes.Buffer)
	tx2.Serialize(buf, did.DIDVersion)
	statedb.Prepare(hash1, hash1, 1)
	statedb.AddDIDLog(idUser2, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*tx2, hash1)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), hash1, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash1)

	privateKeyUser3Str := "4fDnYELy1um12fQPA7V6U953tdMwoUVTsAM5Lp5RF1AU"
	idUser3 := "did:elastos:iidhLBRtSLMzsAuK3uHveLccTfZtCwRreh"
	tx3 := getPayloadDIDInfo(idUser3, "create", jianbinCtrl3PubKeyTest, privateKeyUser3Str)
	hash3 := common.HexToHash("0x1234567")
	buf = new(bytes.Buffer)
	tx3.Serialize(buf, did.DIDVersion)
	statedb.Prepare(hash3, hash3, 1)
	statedb.AddDIDLog(idUser3, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*tx3, hash3)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), hash3, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash3)

	//customized did use controller3 primarykey
	{
		CustomizedDIDTx2 := getCustomizedDIDDocMultiSignFinal(idUser3+"#primary", "create",
			privateKeyUser3Str, custmizeDIDMultyCtrlTest)
		didParam.CustomIDFeeRate = 0
		err := checkCustomizedDID(evm, CustomizedDIDTx2, 20000)
		assert.NoError(t, err)
	}
	//customized did use controller3 authenkey
	{
		//
		ctrl3keywPriKey := "FPHbdqtMZ6j4isEgbn54eKUjFSd84ffbBk7GMadDhiJF"
		CustomizedDIDTx3 := getCustomizedDIDDocMultiSignFinal(idUser3+"#key2", "create",
			ctrl3keywPriKey, custmizeDIDMultyCtrlTest)
		didParam.CustomIDFeeRate = 0
		err := checkCustomizedDID(evm, CustomizedDIDTx3, 20000)
		assert.NoError(t, err)
	}
	//customized did use customized authenkey
	{
		//
		payloadVMKey := "did:elastos:Lindalittlefish05#key2"
		ctrl3keywPriKey := "FPHbdqtMZ6j4isEgbn54eKUjFSd84ffbBk7GMadDhiJF"
		CustomizedDIDTx3 := getCustomizedDIDDocMultiSignFinal(payloadVMKey, "create",
			ctrl3keywPriKey, custmizeDIDMultyCtrlTest)
		didParam.CustomIDFeeRate = 0
		err := checkCustomizedDID(evm, CustomizedDIDTx3, 20000)
		assert.NoError(t, err)
	}
}

func TestJianBinCustomizeDIDMultiCtrlPublicKeyUse(t *testing.T) {

	didParam.IsTest = true
	defer func() {
		didParam.IsTest = false
	}()
	idUser1 := "did:elastos:iqKXrBRrv1vqnaCiHy2kP1LDcmDZmG6hEy"
	privateKeyUser1Str := "3zEQ9H14Edkm7nRqeCopS7xT8ccsSh9pMxdyW4LnYdRv"
	tx1 := getPayloadDIDInfo(idUser1, "create", jianbinCtrl4PubKeyTest, privateKeyUser1Str)
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
	evm.Time = big.NewInt(0)
	evm.BlockNumber = new(big.Int).SetInt64(3)
	evm.chainConfig.DocArraySortHeight = new(big.Int).SetInt64(2)
	evm.chainConfig.CustomizeDIDHeight = new(big.Int).SetInt64(2)
	evm.chainConfig.CheckCustomizeDIDBeginHeight = big.NewInt(0)

	buf := new(bytes.Buffer)
	tx1.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(idUser1, did.Create_DID_Operation, buf.Bytes())
	receipt := getCreateDIDReceipt(*tx1, common.Hash{})
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(common.Hash{})

	privateKeyUser2Str := "4fDnYELy1um12fQPA7V6U953tdMwoUVTsAM5Lp5RF1AU"
	idUser2 := "did:elastos:iidhLBRtSLMzsAuK3uHveLccTfZtCwRreh"
	tx2 := getPayloadDIDInfo(idUser2, "create", jianbinCtrl2PubKeyTest, privateKeyUser2Str)
	hash1 := common.HexToHash("0x1234")
	buf = new(bytes.Buffer)
	tx2.Serialize(buf, did.DIDVersion)
	statedb.Prepare(hash1, hash1, 1)
	statedb.AddDIDLog(idUser2, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*tx2, hash1)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), hash1, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash1)

	privateKeyUser3Str := "BreRiS8SegmJ9pRaxPrLEZvrtiqtdAg7ghqyDQyQ3tun"
	idUser3 := "did:elastos:ibTPLrp758SGtLCzLoiF4VQqCpT7cNCAdh"
	tx3 := getPayloadDIDInfo(idUser3, "create", jianbinCtrl3PubKeyTest, privateKeyUser3Str)
	hash3 := common.HexToHash("0x1234567")
	buf = new(bytes.Buffer)
	tx3.Serialize(buf, did.DIDVersion)
	statedb.Prepare(hash3, hash3, 1)
	statedb.AddDIDLog(idUser3, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*tx3, hash3)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), hash3, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash3)

	//customized did use controller3 primarykey
	{
		CustomizedDIDTx2 := getCustomizedDIDDocMultiSignFinal("did:elastos:Lindalittlefish07"+"#appendfour", "create",
			privateKeyUser3Str, custmizeDIDMultyCtrlTestJB)
		didParam.CustomIDFeeRate = 0
		err := checkCustomizedDID(evm, CustomizedDIDTx2, 20000)
		assert.Equal(t, err.Error(), "not find propoer publickey for payload proof")
	}

}

func outputPayloadToFile(payload types2.Payload, filename string) {
	b11, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("error:", err)
	}
	dest, err := os.Create(filename)
	if err != nil {
		return
	}
	defer dest.Close()
	dest.Write(b11)
}

func TestIsLetterOrNumber(t *testing.T) {
	assert.True(t, IsLetterOrNumber("alice"))
	assert.True(t, IsLetterOrNumber("alice1"))
	assert.True(t, IsLetterOrNumber("Alice2"))
	assert.True(t, IsLetterOrNumber("123"))
	assert.False(t, IsLetterOrNumber("艾丽斯"))
	assert.False(t, IsLetterOrNumber(":alice"))
	assert.False(t, IsLetterOrNumber("alice bob"))
	assert.False(t, IsLetterOrNumber("(alice)"))
	assert.False(t, IsLetterOrNumber("("))
	assert.False(t, IsLetterOrNumber(")"))
	assert.False(t, IsLetterOrNumber("["))
	assert.False(t, IsLetterOrNumber("]"))
	assert.False(t, IsLetterOrNumber("{"))
	assert.False(t, IsLetterOrNumber("}"))
	assert.False(t, IsLetterOrNumber("<"))
	assert.False(t, IsLetterOrNumber(">"))
	assert.False(t, IsLetterOrNumber("+"))
	assert.False(t, IsLetterOrNumber("-"))
	assert.False(t, IsLetterOrNumber("*"))
	assert.False(t, IsLetterOrNumber("~"))
	assert.False(t, IsLetterOrNumber("!"))
	assert.False(t, IsLetterOrNumber("@"))
	assert.False(t, IsLetterOrNumber("#"))
	assert.False(t, IsLetterOrNumber("$"))
	assert.False(t, IsLetterOrNumber("%"))
	assert.False(t, IsLetterOrNumber("^"))
	assert.False(t, IsLetterOrNumber("&"))
	assert.False(t, IsLetterOrNumber(":"))
	assert.False(t, IsLetterOrNumber(";"))
	assert.False(t, IsLetterOrNumber("'"))
	assert.False(t, IsLetterOrNumber(""))
	assert.False(t, IsLetterOrNumber(","))
	assert.False(t, IsLetterOrNumber("."))
	assert.False(t, IsLetterOrNumber("?"))
	assert.False(t, IsLetterOrNumber("/"))
	assert.False(t, IsLetterOrNumber(" "))
}

func TestSortDoc(t *testing.T) {
	info := new(did.DIDDoc)
	json.Unmarshal(barzIDDocByts, info)
	sortDocSlice(info)
	fmt.Println(info)
}

//todo
func TestCredentialTx2(t *testing.T) {
	return
	id1 := "did:elastos:ibTPLrp758SGtLCzLoiF4VQqCpT7cNCAdh"
	privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"
	tx1 := getPayloadDIDInfo(id1, "create", jianbinCtrl3PubKeyTest, privateKey1Str)

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))

	buf := new(bytes.Buffer)
	tx1.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
	receipt := getCreateDIDReceipt(*tx1, common.Hash{})
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(common.Hash{})

	//customized persist Lindalittlefish20
	tx3hash := common.HexToHash("0x2345")
	statedb.Prepare(tx3hash, tx3hash, 1)
	CustomizedDIDTx1 := getCustomizedDIDTx(id1, "create", Lindalittlefish20DocByte, privateKey1Str)
	buf = new(bytes.Buffer)
	CustomizedDIDTx1.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*CustomizedDIDTx1, tx3hash)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), tx3hash, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(tx3hash)

	err := checkDIDTransaction(declareCredDocPayload, statedb)
	assert.NoError(t, err)
	payload := new(did.DIDPayload)
	if err := json.Unmarshal(declareCredDocPayload, payload); err != nil {
	}
	tx4Hash := common.HexToHash("0x3456")
	credentialID := "did:elastos:Lindalittlefish20#id_normal_issuer_normal_Lindaprofile07"
	buf = new(bytes.Buffer)
	statedb.Prepare(tx4Hash, tx4Hash, 1)
	payload.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(credentialID, did.Declare_Verifiable_Credential_Operation, buf.Bytes())
	receipt = getDeclareDIDReceipt(*payload)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), tx4Hash, 0, types.Receipts{receipt}, 0)
	err4 := rawdb.PersistVerifiableCredentialTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(tx4Hash), 100, 123456, tx4Hash)
	assert.NoError(t, err4)

	owner, _ := did.GetController(credentialID)
	owner = strings.ToLower(owner)
	credential, _ := rawdb.GetAllDIDVerifCredentials(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), []byte(owner), 0, 100)
	assert.EqualValues(t, len(credential.Credentials), 1)
	assert.EqualValues(t, credential.Credentials[0], credentialID)
}

func Test_checkCustIDOverMaxExpireHeight(t *testing.T) {
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.chainConfig.MaxExpiredHeight = big.NewInt(5)

	type args struct {
		evm            *EVM
		custID         string
		operation      string
		curBlockNumber uint64
		expiredHeight  uint64
		deactivated    bool
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			//cur Block number 7 > expired height 1+MaxExpiredHeight 5   so can recreate
			"over max expired height and recreate  ",
			args{evm,
				"cust1",
				"create",
				7,
				1,
				false},
			false,
		},
		// TODO: Add test cases.
		{
			//cur Block number 7 > expired height 1+MaxExpiredHeight 5   so must recreate
			"over max expired height and update  ",
			args{evm,
				"cust1",
				"update",
				7,
				1,
				false},
			true,
		},
		// TODO: Add test cases.
		{
			//cur Block number 7 <= expired height 2+MaxExpiredHeight 5   so can not recreate
			"not over max expired height and recreate  ",
			args{evm,
				"cust1",
				"create",
				7,
				2,
				false},
			true,
		},
		{
			//cur Block number 7 <= expired height 2+MaxExpiredHeight 5   so can update
			"not over max expired height and update  ",
			args{evm,
				"cust1",
				"update",
				7,
				2,
				false},
			false,
		},
		{
			//cur Block number 7 <= expired height 2+MaxExpiredHeight 5  but deactiveated so can not update
			"not over max expired height and update and deactivated ",
			args{evm,
				"cust1",
				"update",
				7,
				2,
				true},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lowerID := strings.ToLower(tt.args.custID)

			db := statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore)
			evm.BlockNumber = new(big.Int).SetUint64(tt.args.curBlockNumber)

			rawdb.PersistIsDID(db, []byte(lowerID), 0)
			if tt.args.deactivated {
				hash3 := common.HexToHash("0x2345")
				buf := new(bytes.Buffer)
				txDeactivate := getDeactivateCustomizedDIDTx(lowerID, "id1", "privateKey1Str")
				txDeactivate.Serialize(buf, did.DIDVersion)
				statedb.Prepare(hash3, hash3, 1)

				statedb.AddDIDLog(lowerID, did.Deactivate_DID_Operation, buf.Bytes())
				rawdb.PersistDeactivateDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore),
					statedb.GetDIDLog(hash3), hash3)
			}
			rawdb.PersistRegisterDIDExpiresHeight(db, []byte(lowerID), tt.args.expiredHeight)
			if err := checkCustIDOverMaxExpireHeight(tt.args.evm, tt.args.custID, tt.args.operation); (err != nil) != tt.wantErr {
				t.Errorf("checkCustIDOverMaxExpireHeight() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

//  invalid revoke   first  fake issuer revoke then owner revoke
func TestOwnerRevokeAfterFakeRevokeTx(t *testing.T) {
	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	id1 := "did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
	privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	db := statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore)
	{

		hash1 := common.HexToHash("0x00234")
		statedb.Prepare(hash1, hash1, 1)
		tx1 := getPayloadDIDInfo(id1, "create", docDocBytes, privateKey1Str)
		buf := new(bytes.Buffer)
		tx1.Serialize(buf, did.DIDVersion)
		statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
		receipt := getCreateDIDReceipt(*tx1, hash1)
		rawdb.WriteReceipts(db, hash1, 0, types.Receipts{receipt}, 0)
		statedb.RemoveDIDLog(hash1)
	}
	{
		//customized did:elastos:foobar have iWFAUYhTa35c1fPe3iCJvihZHx6quumnym controller
		tx3hash := common.HexToHash("0x2345678")
		statedb.Prepare(tx3hash, tx3hash, 1)
		CustomizedDIDTx1 := getCustomizedDIDTx(id1, "create", custIDSingleSignDocBytes1, privateKey1Str)
		buf := new(bytes.Buffer)
		CustomizedDIDTx1.Serialize(buf, did.DIDVersion)
		statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
		receipt := getCreateDIDReceipt(*CustomizedDIDTx1, tx3hash)
		rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), tx3hash, 0, types.Receipts{receipt}, 0)
		statedb.RemoveDIDLog(tx3hash)
	}

	id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	//	regisgter did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB
	hash2 := common.HexToHash("0x2345")
	statedb.Prepare(hash2, hash2, 1)
	tx2 := getPayloadDIDInfo(id2, "create", issuerDocByts, privateKey2Str)
	buf := new(bytes.Buffer)
	tx2.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id2, did.Create_DID_Operation, buf.Bytes())
	receipt := getCreateDIDReceipt(*tx2, hash2)
	rawdb.WriteReceipts(db, hash2, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash2)

	verifableCredentialRevokeTx := getRevokeVerifiableCredentialTx("did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym#primary",
		"did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile", privateKey1Str)

	data, err := json.Marshal(verifableCredentialRevokeTx)

	assert.NoError(t, err)
	err = checkDIDTransaction(data, statedb)
	assert.NoError(t, err)

	buf = new(bytes.Buffer)
	hash := common.Hash{}
	statedb.Prepare(hash, hash, 1)
	verifableCredentialRevokeTx.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile", did.Revoke_Verifiable_Credential_Operation, buf.Bytes())
	receipt = getDeclareDIDReceipt(*verifableCredentialRevokeTx)
	rawdb.WriteReceipts(db, common.Hash{}, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash)

	//did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile isuer did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB
	//owner did:elastos:foobar
	verifableCredentialRevokeTx2 := getRevokeVerifiableCredentialTx("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#primary",
		"did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile", privateKey2Str)
	data, err = json.Marshal(verifableCredentialRevokeTx2)
	assert.NoError(t, err)
	err = checkDIDTransaction(data, statedb)
	assert.NoError(t, err)

	//assert.EqualError(t, err, "VerifiableCredential revoked again")

	buf = new(bytes.Buffer)
	hash = common.HexToHash("0x234533333")
	statedb.Prepare(hash, hash, 1)
	verifableCredentialRevokeTx2.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile", did.Revoke_Verifiable_Credential_Operation, buf.Bytes())
	receipt = getDeclareDIDReceipt(*verifableCredentialRevokeTx2)
	rawdb.WriteReceipts(db, hash, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash)

	ctrls, err := rawdb.GetRevokeCredentialCtrls(db, []byte("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile"))
	fmt.Println(ctrls)
}

func TestFakeRevokeAfterOwnerRevokeTx(t *testing.T) {
	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	id1 := "did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
	privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	db := statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore)
	{

		hash1 := common.HexToHash("0x00234")
		statedb.Prepare(hash1, hash1, 1)
		tx1 := getPayloadDIDInfo(id1, "create", docDocBytes, privateKey1Str)
		buf := new(bytes.Buffer)
		tx1.Serialize(buf, did.DIDVersion)
		statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
		receipt := getCreateDIDReceipt(*tx1, hash1)
		rawdb.WriteReceipts(db, hash1, 0, types.Receipts{receipt}, 0)
		statedb.RemoveDIDLog(hash1)
	}
	{
		tx3hash := common.HexToHash("0x2345678")
		statedb.Prepare(tx3hash, tx3hash, 1)
		CustomizedDIDTx1 := getCustomizedDIDTx(id1, "create", custIDSingleSignDocBytes1, privateKey1Str)
		buf := new(bytes.Buffer)
		CustomizedDIDTx1.Serialize(buf, did.DIDVersion)
		statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
		receipt := getCreateDIDReceipt(*CustomizedDIDTx1, tx3hash)
		rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), tx3hash, 0, types.Receipts{receipt}, 0)
		statedb.RemoveDIDLog(tx3hash)
	}

	id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	//	regisgter did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB
	hash2 := common.HexToHash("0x2345")
	statedb.Prepare(hash2, hash2, 1)
	tx2 := getPayloadDIDInfo(id2, "create", issuerDocByts, privateKey2Str)
	buf := new(bytes.Buffer)
	tx2.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id2, did.Create_DID_Operation, buf.Bytes())
	receipt := getCreateDIDReceipt(*tx2, hash2)
	rawdb.WriteReceipts(db, hash2, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash2)

	verifableCredentialRevokeTx := getRevokeVerifiableCredentialTx("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#primary",
		"did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile", privateKey2Str)
	data, err := json.Marshal(verifableCredentialRevokeTx)

	assert.NoError(t, err)
	err = checkDIDTransaction(data, statedb)
	assert.NoError(t, err)

	buf = new(bytes.Buffer)
	hash := common.Hash{}
	statedb.Prepare(hash, hash, 1)
	verifableCredentialRevokeTx.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile", did.Revoke_Verifiable_Credential_Operation, buf.Bytes())
	receipt = getDeclareDIDReceipt(*verifableCredentialRevokeTx)
	rawdb.WriteReceipts(db, common.Hash{}, 0, types.Receipts{receipt}, 0)
	statedb.RemoveDIDLog(hash)

	verifableCredentialRevokeTx2 := getRevokeVerifiableCredentialTx("did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym#primary",
		"did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile", privateKey1Str)

	data, err = json.Marshal(verifableCredentialRevokeTx2)
	assert.NoError(t, err)
	err = checkDIDTransaction(data, statedb)
	assert.EqualError(t, err, "already have valid revoked")

	buf = new(bytes.Buffer)
	hash = common.HexToHash("0x234533333")
	statedb.Prepare(hash, hash, 1)
	verifableCredentialRevokeTx2.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile", did.Revoke_Verifiable_Credential_Operation, buf.Bytes())
	receipt = getDeclareDIDReceipt(*verifableCredentialRevokeTx2)
	rawdb.WriteReceipts(db, hash, 0, types.Receipts{receipt}, 0)

	statedb.RemoveDIDLog(hash)

	ctrls, err := rawdb.GetRevokeCredentialCtrls(db, []byte("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile"))
	fmt.Println(ctrls)

}
func TestMainNetCheckRegisterDID(t *testing.T) {
	//todo if use jsonmarshal open this testcase
	return
	id1 := "did:elastos:id5PQX43gxxxDiii2fhhSEGguYpZbHdBNg"
	privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"
	tx1 := getPayloadDIDInfo(id1, "create", specialCharacterDocBytes, privateKey1Str)

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	docBytes, err := json.Marshal(tx1)
	assert.NoError(t, err)
	err3 := checkDIDTransactionAfterMigrateHeight(docBytes, statedb)
	assert.NoError(t, err3)

}
