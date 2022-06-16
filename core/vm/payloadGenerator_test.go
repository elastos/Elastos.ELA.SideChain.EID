package vm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/elastos/Elastos.ELA.SideChain.EID/common"
	"github.com/elastos/Elastos.ELA.SideChain.EID/core/rawdb"
	"github.com/elastos/Elastos.ELA.SideChain.EID/core/state"
	"github.com/elastos/Elastos.ELA.SideChain.EID/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.EID/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.EID/ethdb"
	"github.com/elastos/Elastos.ELA.SideChain.EID/params"
	"github.com/elastos/Elastos.ELA.SideChain/service"
	elacom "github.com/elastos/Elastos.ELA/common"

	"github.com/stretchr/testify/assert"
)

/*
this file is used to generate tx payload who format is  head, payload proof
use .json file to formate doc and Test case to generate doc sign.
PayloadGenerator is the helper struct
*/

var  gentor PayloadGenerator

func TestReverse(t *testing.T){
	hash,_ := elacom.Uint256FromHexString("bedeaad0ce7eb8338546700ccaf84788c21219c560c8dd99f46b60e0a02ce946")

	hashReverse := service.ToReversedString(*hash)
	fmt.Println("hashReverse", hashReverse)
}

func  TestChangUser2DocAndSaveToJsonJianBin2(t *testing.T) {

	//s.validator.didParam.CustomIDFeeRate = 0
	//privateKeyUser1Str := "FPHbdqtMZ6j4isEgbn54eKUjFSd84ffbBk7GMadDhiJF"
	privateKeyUser1Str := gentor.TestFromHexStrPrivateToBase58PriJianBin("d5b92946c4a3df330b557512deb85cda3b055c7e2477c5d676dbe4ada2c9636c")
	//publicKeyUser1Str := "2Akc64WFqfbciM9TxpanipMG5eGmDafdMUohmNpqQZaWm"
	publicKeyUser1Str := gentor.TestFromHexStrPublicToBase58PublicJianBin("03eeaaac10ff279cba8706e86bbd36d19a4aa967df58e9c41cbe6a44770d68c612")
	//privateKeyUser2Str := "AqBB8Uur4QwwBtFPeA2Yd5yF2Ni45gyz2osfFcMcuP7J"
	//publicKeyUser2Str := "kTYQhMtoimm9wV3vy4q9EVy4Z1WxRqxhvngztdGo1Dmc"
	privateKeyUser2Str := gentor.TestFromHexStrPrivateToBase58PriJianBin("6f2d91b0b4dd03fad560de4e7bdc7614e71cf348a6736c491fb6c8200dcbb6c3")
	publicKeyUser2Str := gentor.TestFromHexStrPublicToBase58PublicJianBin("030a9f1a9aed77d599d3377b4f93ef9141e3784e3a99e8bf10a02c1c443e6637e7")
	idUser2 := "did:elastos:iYm2nAMXetnhtQYzF4nAa8dDKhfnxYqNDQ"
	//todo
	veriCrePrivateKeys := []string{
		"FPHbdqtMZ6j4isEgbn54eKUjFSd84ffbBk7GMadDhiJF", "BreRiS8SegmJ9pRaxPrLEZvrtiqtdAg7ghqyDQyQ3tun",
	}
	veriCrePublicKeys := []string{
		"2Akc64WFqfbciM9TxpanipMG5eGmDafdMUohmNpqQZaWm", "yem32dZq2TVmjLLDe7y6Svj3Ag7qQtjUQ6P7nGdE6eTc",
	}
	txMyChangDOC := gentor.getPayloadDIDInfoChangeDoc(idUser2, "create", jianbinCtrl5PubKeyTest,
		privateKeyUser1Str, publicKeyUser1Str, privateKeyUser2Str, publicKeyUser2Str,
		"#key2", veriCrePrivateKeys, veriCrePublicKeys)
	//	err4 := s.validator.checkDIDTransaction(txMyChangDOC, 0, 0)
	//	s.NoError(err4)
	//	s.Equal(err4.Error(), "DID NOT FIND PUBLIC KEY OF VerificationMethod")
	//	fmt.Println(err4.Error())
	fileName := "payload.create.json"
	outputPayloadToFile(txMyChangDOC, fileName)
	//tx2 := getDIDTx(idUser2, "create", idUser2DocByts, privateKeyUser2Str)
	//batch2 := s.validator.Store.NewBatch()
	//err2 := s.validator.Store.PersistRegisterDIDTx(batch2, []byte(idUser2), tx2,
	//  100, 123456)
	//s.NoError(err2)
	//batch2.Commit()
	var TestCreateID = func (t *testing.T) {
		{
			id1 := "did:elastos:iYm2nAMXetnhtQYzF4nAa8dDKhfnxYqNDQ"
			privateKey1Str := "FPHbdqtMZ6j4isEgbn54eKUjFSd84ffbBk7GMadDhiJF"
			tx1 := getPayloadDIDInfo(id1, "create", jianbinCtrl5PubKeyTest, privateKey1Str)

			//outputPayloadToFile(tx1, "user2.dest.payload.json")
			statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
			evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
			evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
			evm.Time=big.NewInt(0)
			evm.BlockNumber = new(big.Int).SetInt64(1)
			evm.chainConfig.DocArraySortHeight = new(big.Int).SetInt64(2)
			evm.chainConfig.CustomizeDIDHeight = big.NewInt(3000000)
			evm.chainConfig.MaxExpiredHeight = big.NewInt(100)

			buf := new(bytes.Buffer)
			tx1.Serialize(buf, did.DIDVersion)

			statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
			db := statedb.Database().TrieDB().DiskDB()
			err1 := rawdb.PersistRegisterDIDTx(db.(ethdb.KeyValueStore),db.(ethdb.KeyValueReader), statedb.GetDIDLog(common.Hash{}), 0, 100)
			assert.NoError(t, err1)
			statedb.RemoveDIDLog(common.Hash{})
		}
		didParam.IsTest = true
		var changeDocPayload2          []byte
		changeDocPayload2, _ = LoadJsonData(fileName)
		err := checkDIDTransactionAfterMigrateHeight(changeDocPayload2, nil)
		assert.NoError(t, err)
	}
	TestCreateID(t)
}


func TestChangUser2DocAndSaveToJsonJianBin2_Update(t *testing.T) {


	privateKeyUser1Str := gentor.TestFromHexStrPrivateToBase58PriJianBin("1d5cf8daa96de73b81700b97f3809fe68e254b182d7fbcd64000a8796bb27a7f")
	publicKeyUser1Str := gentor.TestFromHexStrPublicToBase58PublicJianBin("03dd9576e700601b05a2561f2781d746ce93ddcad05df2fbea06fcccfb69eec585")
	privateKeyUser2Str := gentor.TestFromHexStrPrivateToBase58PriJianBin("6f2d91b0b4dd03fad560de4e7bdc7614e71cf348a6736c491fb6c8200dcbb6c3")
	publicKeyUser2Str := gentor.TestFromHexStrPublicToBase58PublicJianBin("030a9f1a9aed77d599d3377b4f93ef9141e3784e3a99e8bf10a02c1c443e6637e7")

	//previousTxid := "5276745231398788c8aa1ef68c4a81f7c27fd2260c379c7923b4c71129777b7a"
	idUser2 := "did:elastos:iYm2nAMXetnhtQYzF4nAa8dDKhfnxYqNDQ"
	//todo jianbinCtrl5PubKeyTest
	veriCrePrivateKeys := []string{
		"FPHbdqtMZ6j4isEgbn54eKUjFSd84ffbBk7GMadDhiJF", "BreRiS8SegmJ9pRaxPrLEZvrtiqtdAg7ghqyDQyQ3tun",
	}
	veriCrePublicKeys := []string{
		"2Akc64WFqfbciM9TxpanipMG5eGmDafdMUohmNpqQZaWm", "yem32dZq2TVmjLLDe7y6Svj3Ag7qQtjUQ6P7nGdE6eTc",
	}

	{
		statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
		evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
		evm.BlockNumber = new(big.Int).SetInt64(1)
		evm.chainConfig.DocArraySortHeight = new(big.Int).SetInt64(2)
		evm.chainConfig.MaxExpiredHeight = new(big.Int).SetInt64(100)
		evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
		hash1 := common.HexToHash( "e71e0aee28c8119c4e8069fb9faa22c0")
		statedb.Prepare(hash1, hash1, 1)

		user1 := "did:elastos:iYm2nAMXetnhtQYzF4nAa8dDKhfnxYqNDQ"
		user1PrivateKeyStr := "FPHbdqtMZ6j4isEgbn54eKUjFSd84ffbBk7GMadDhiJF"
		user1TX := getPayloadDIDInfo(user1, "create", jianbinCtrl5PubKeyTest, user1PrivateKeyStr)
		buf := new(bytes.Buffer)
		user1TX.Serialize(buf, did.DIDVersion)
		statedb.AddDIDLog(user1TX.DIDDoc.ID, did.Create_DID_Operation, buf.Bytes())
		receipt := getCreateDIDReceipt(*user1TX)
		rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), hash1, 0, types.Receipts{receipt})
		db := statedb.Database().TrieDB().DiskDB()
		user1Err := rawdb.PersistRegisterDIDTx(db.(ethdb.KeyValueStore),db.(ethdb.KeyValueReader), statedb.GetDIDLog(hash1), 0, 0)
		assert.NoError(t, user1Err)
		statedb.RemoveDIDLog(hash1)

		previousTxid := hash1.String()[2:]
		//
		txMyChangDOC := gentor.getPayloadDIDInfoChangeDoc_update(idUser2, "update", jianbinCtrl5PubKeyTest,
			privateKeyUser1Str, publicKeyUser1Str, privateKeyUser2Str, publicKeyUser2Str,
			"#key3", veriCrePrivateKeys, veriCrePublicKeys, previousTxid)

		outputPayloadToFile(txMyChangDOC, "user2.dest.payload.json")
		//transferTx := getCustomizedDIDTransferTx(user4, "transfer", bazNewIDDocByts, batTTDocByts, user4PrivateKeyStr, user2PrivateKeyStr, txhash)

		didParam.CustomIDFeeRate = 0
		didParam.IsTest = true

		data, err := json.Marshal(txMyChangDOC)
		assert.NoError(t, err)
		transferErr := checkDIDTransactionAfterMigrateHeight(data, statedb)
		assert.NoError(t, transferErr)
		didParam.IsTest = false
	}
}

func  TestChangUser2DocAndSaveToJsonJianBin2_Deactive(t *testing.T) {


	privateKeyUser1Str := gentor.TestFromHexStrPrivateToBase58PriJianBin("1d5cf8daa96de73b81700b97f3809fe68e254b182d7fbcd64000a8796bb27a7f")
	publicKeyUser1Str := gentor.TestFromHexStrPublicToBase58PublicJianBin("03dd9576e700601b05a2561f2781d746ce93ddcad05df2fbea06fcccfb69eec585")
	privateKeyUser2Str := gentor.TestFromHexStrPrivateToBase58PriJianBin("6f2d91b0b4dd03fad560de4e7bdc7614e71cf348a6736c491fb6c8200dcbb6c3")
	publicKeyUser2Str := gentor.TestFromHexStrPublicToBase58PublicJianBin("030a9f1a9aed77d599d3377b4f93ef9141e3784e3a99e8bf10a02c1c443e6637e7")
	idUser2 := "did:elastos:ijb8oNP3ZMKP6N5swJCoiYtoUbomAK13Xy"
	veriCrePrivateKeys := []string{
		"FPHbdqtMZ6j4isEgbn54eKUjFSd84ffbBk7GMadDhiJF", "BreRiS8SegmJ9pRaxPrLEZvrtiqtdAg7ghqyDQyQ3tun",
	}
	veriCrePublicKeys := []string{
		"2Akc64WFqfbciM9TxpanipMG5eGmDafdMUohmNpqQZaWm", "yem32dZq2TVmjLLDe7y6Svj3Ag7qQtjUQ6P7nGdE6eTc",
	}
	txMyChangDOC := gentor.getPayloadDIDInfoChangeDoc_Deactive(idUser2, "deactivate", jianbinCtrl5PubKeyTest,
		privateKeyUser1Str, publicKeyUser1Str, privateKeyUser2Str, publicKeyUser2Str,
		"#primary", veriCrePrivateKeys, veriCrePublicKeys)
	outputPayloadToFile(txMyChangDOC, "user2.dest.payload.json")
}

//todo
func  TestChangUser2DocAndSaveToJsonJianBin_VerifiableCredential_Declare(t *testing.T) {
	return
	privateKeyUser1Str := gentor.TestFromHexStrPrivateToBase58PriJianBin("1d5cf8daa96de73b81700b97f3809fe68e254b182d7fbcd64000a8796bb27a7f")
	publicKeyUser1Str := gentor.TestFromHexStrPublicToBase58PublicJianBin("03dd9576e700601b05a2561f2781d746ce93ddcad05df2fbea06fcccfb69eec585")
	privateKeyUser2Str2 := gentor.TestFromHexStrPrivateToBase58PriJianBin("dc8d5cdd829ede8086bb845d72cefc50ea76a19ef2107819290846fd8d18140f")
	publicKeyUser2Str2 := gentor.TestFromHexStrPublicToBase58PublicJianBin("027e12b64d2dc0272e49beb1cfcb51cebf977663742ba964348cc4bb98a433f2a1")
	privateKeyUser2Str3 := gentor.TestFromHexStrPrivateToBase58PriJianBin("6f2d91b0b4dd03fad560de4e7bdc7614e71cf348a6736c491fb6c8200dcbb6c3")
	publicKeyUser2Str3 := gentor.TestFromHexStrPublicToBase58PublicJianBin("030a9f1a9aed77d599d3377b4f93ef9141e3784e3a99e8bf10a02c1c443e6637e7")
	docPrivateKeyUserArray := []string{
		privateKeyUser2Str2, privateKeyUser2Str3,
	}
	docPublicKeyUserArray := []string{
		publicKeyUser2Str2, publicKeyUser2Str3,
	}
	idUser2 := "did:elastos:Lindalittlefish23"
	veriCrePrivateKeys := "FPHbdqtMZ6j4isEgbn54eKUjFSd84ffbBk7GMadDhiJF"

	veriCrePublicKeys := "2Akc64WFqfbciM9TxpanipMG5eGmDafdMUohmNpqQZaWm"
	//getPayloadDIDInfoChangeDoc_customterDID_verifiableCredential
	txMyChangDOC := gentor.getPayloadDIDInfoChangeDoc_customterDID_verifiableCredential(idUser2, "declare", jianbinCtrl5PubKeyTest,
		privateKeyUser1Str, publicKeyUser1Str, docPrivateKeyUserArray, docPublicKeyUserArray,
		"#key3", veriCrePrivateKeys, veriCrePublicKeys)
	outputPayloadToFile(txMyChangDOC, "user2.dest.payload.json")
}
func  TestChangUser2DocAndSaveToJsonJianBin_VerifiableCredential_Revoke(t *testing.T) {
	return
	privateKeyUser1Str := gentor.TestFromHexStrPrivateToBase58PriJianBin("d5b92946c4a3df330b557512deb85cda3b055c7e2477c5d676dbe4ada2c9636c")
	publicKeyUser1Str := gentor.TestFromHexStrPublicToBase58PublicJianBin("03eeaaac10ff279cba8706e86bbd36d19a4aa967df58e9c41cbe6a44770d68c612")
	idUser2 := "did:elastos:ibTPLrp758SGtLCzLoiF4VQqCpT7cNCAdh"
	verifiableCredentialID := "did:elastos:Lindalittlefish23#id_customerDID_issuer_customerDID_nodeclare_Lindaprofile215"
	txMyChangDOC := gentor.getPayloadDIDInfoChangeDoc_customterDID_verifiableCredential_Revoke(idUser2, "revoke",
		privateKeyUser1Str, publicKeyUser1Str, "#key2", verifiableCredentialID)
	outputPayloadToFile(txMyChangDOC, "user2.dest.payload.json")

}