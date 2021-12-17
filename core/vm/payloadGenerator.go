
// Copyright 2014 The Elastos.ELA.SideChain.EID Authors
// This file is part of the Elastos.ELA.SideChain.EID library.
//
// The Elastos.ELA.SideChain.EID library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The Elastos.ELA.SideChain.EID library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the Elastos.ELA.SideChain.EID library. If not, see <http://www.gnu.org/licenses/>.
package vm

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/elastos/Elastos.ELA.SideChain.EID/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.EID/core/vm/did/base64url"
	"github.com/elastos/Elastos.ELA/crypto"

	"github.com/btcsuite/btcutil/base58"
)

//generate sign for json doc
type  PayloadGenerator struct {

}
func (s *PayloadGenerator) TestFromHexStrPrivateToBase58PriJianBin(privatekeyhexstr string) string {
	hexString := privatekeyhexstr
	privateKey, _ := hex.DecodeString(hexString)
	base58PrivateKey := base58.Encode(privateKey)
	fmt.Println("base58PrivateKey", base58PrivateKey)
	return base58PrivateKey
}

func (s *PayloadGenerator) TestFromHexStrPublicToBase58PublicJianBin(publickeyhexstr string) string {
	//hexString := "0349babf911ba44e601347659330fa907fcfc56349f21ffe75dbe6b6b6b0139793"
	hexString := publickeyhexstr
	privateKey, _ := hex.DecodeString(hexString)
	base58PublicKey := base58.Encode(privateKey)
	//  fmt.Println("base58PublicKey nB5wmcqnJvQtYS3Xwuay9VUkwxzopiLEhTMStSGoDfAL ", base58PublicKey)
	fmt.Println("base58PublicKey：", base58PublicKey)
	return base58PublicKey
}



//create
func (s *PayloadGenerator)getPayloadDIDInfoChangeDoc(id string, didDIDPayload string, docBytes []byte, privateKey1Str, publicKey1Str,
	privateKey2Str, publicKey2Str, VMKey string, privateKeyVerCreStr, publicKeyVerCrStr []string) *did.DIDPayload {
	//pBytes := getDIDPayloadBytes(id)
	privateKey1 := base58.Decode(privateKey1Str)
	privateKey2 := base58.Decode(privateKey2Str)
	fmt.Println(" docBytes  before chg", string(docBytes))
	info := new(did.DIDDoc)
	json.Unmarshal(docBytes, info)

	sortDocSlice(info)
	///////////////////////////////////////////
	//doc proof sign create and verify

	{
		//credential proof sign and verify
		/////////////////////////////////////
		for i, v := range info.DIDPayloadData.VerifiableCredential {
			fmt.Println("VerifiableCredential ", i, "privateKeyVerCreStr", privateKeyVerCreStr[i])
			fmt.Println("VerifiableCredential data ", string(v.VerifiableCredentialData.GetData()))
			privateKeyVerCre := base58.Decode(privateKeyVerCreStr[i])
			signVerCre, _ := crypto.Sign(privateKeyVerCre, v.VerifiableCredentialData.GetData())
			info.DIDPayloadData.VerifiableCredential[i].Proof.Signature = base64url.EncodeToString(signVerCre)
			fmt.Println("VerifiableCredential Signature ", info.DIDPayloadData.VerifiableCredential[i].Proof.Signature)
			fmt.Println("VerifiableCredential publicKeyVerCrStr[i]", publicKeyVerCrStr[i])
			publickey := base58.Decode(publicKeyVerCrStr[i])
			pubkey, err := crypto.DecodePoint(publickey)
			err = crypto.Verify(*pubkey, v.VerifiableCredentialData.GetData(), signVerCre)
			fmt.Println("getPayloadDIDInfo VerifiableCredential 1111", err)

		}

		/////////////////////////////////
		sign, _ := crypto.Sign(privateKey2, info.DIDPayloadData.GetData())
		docProof := &did.DocProof{}
		fmt.Println("getPayloadDIDInfo Verify 3333333------", info.Proof)
		if err := Unmarshal(info.Proof, docProof); err != nil {
			panic("error should not be here")
		}
		docProof.SignatureValue = base64url.EncodeToString(sign)
		publickey := base58.Decode(publicKey2Str)
		pubkey, err := crypto.DecodePoint(publickey)
		fmt.Println(err)
		//fmt.Println("1111111 public key ", "kTYQhMtoimm9wV3vy4q9EVy4Z1WxRqxhvngztdGo1Dmc")
		//fmt.Println("1111111 SignatureValue ", docProof.SignatureValue)
		//fmt.Println("1111111 info.GetData()", string(info.GetData()))
		//info.Proof = docProof
		err = crypto.Verify(*pubkey, info.DIDPayloadData.GetData(), sign)
		fmt.Println("getPayloadDIDInfo Verify 1111", err)
		info.Proof = docProof
	}
	fmt.Println(" docBytes after chg", string(info.GetData()))

	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     didDIDPayload,
			//create
			PreviousTxid: "",
			//update
			//PreviousTxid:  "af1f64a6d00a79c2b82919805ee21de9bc3782168a60175f0ea5509c81192111",
		},
		Payload: base64url.EncodeToString(info.GetData()),
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: id + VMKey, //primary
		},
		DIDDoc: info,
	}
	//payload proof sign create and verify
	sign, _ := crypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}

//update
func (s *PayloadGenerator)getPayloadDIDInfoChangeDoc_update(id string, didDIDPayload string, docBytes []byte, privateKey1Str, publicKey1Str,
	privateKey2Str, publicKey2Str, VMKey string, privateKeyVerCreStr, publicKeyVerCrStr []string, previousTxid string) *did.DIDPayload {
	//pBytes := getDIDPayloadBytes(id)
	privateKey1 := base58.Decode(privateKey1Str)
	privateKey2 := base58.Decode(privateKey2Str)
	fmt.Println(" docBytes  before chg", string(docBytes))
	info := new(did.DIDDoc)
	json.Unmarshal(docBytes, info)

	sortDocSlice(info)
	///////////////////////////////////////////
	//doc proof sign create and verify

	{
		//credential proof sign and verify
		/////////////////////////////////////
		for i, v := range info.DIDPayloadData.VerifiableCredential {
			fmt.Println("VerifiableCredential ", i, "privateKeyVerCreStr", privateKeyVerCreStr[i])
			fmt.Println("VerifiableCredential data ", string(v.VerifiableCredentialData.GetData()))
			privateKeyVerCre := base58.Decode(privateKeyVerCreStr[i])
			signVerCre, _ := crypto.Sign(privateKeyVerCre, v.VerifiableCredentialData.GetData())
			info.DIDPayloadData.VerifiableCredential[i].Proof.Signature = base64url.EncodeToString(signVerCre)
			fmt.Println("VerifiableCredential Signature ", info.DIDPayloadData.VerifiableCredential[i].Proof.Signature)
			fmt.Println("VerifiableCredential publicKeyVerCrStr[i]", publicKeyVerCrStr[i])
			publickey := base58.Decode(publicKeyVerCrStr[i])
			pubkey, err := crypto.DecodePoint(publickey)
			err = crypto.Verify(*pubkey, v.VerifiableCredentialData.GetData(), signVerCre)
			fmt.Println("getPayloadDIDInfo VerifiableCredential 1111", err)

		}

		/////////////////////////////////
		sign, _ := crypto.Sign(privateKey2, info.DIDPayloadData.GetData())
		docProof := &did.DocProof{}
		fmt.Println("getPayloadDIDInfo Verify 3333333------", info.Proof)
		if err := Unmarshal(info.Proof, docProof); err != nil {
			panic("error should not be here")
		}
		docProof.SignatureValue = base64url.EncodeToString(sign)
		publickey := base58.Decode(publicKey2Str)
		pubkey, err := crypto.DecodePoint(publickey)
		fmt.Println(err)
		//fmt.Println("1111111 public key ", "kTYQhMtoimm9wV3vy4q9EVy4Z1WxRqxhvngztdGo1Dmc")
		//fmt.Println("1111111 SignatureValue ", docProof.SignatureValue)
		//fmt.Println("1111111 info.GetData()", string(info.GetData()))
		//info.Proof = docProof
		err = crypto.Verify(*pubkey, info.DIDPayloadData.GetData(), sign)
		fmt.Println("getPayloadDIDInfo Verify 1111", err)
		info.Proof = docProof
	}
	fmt.Println(" docBytes after chg", string(info.GetData()))

	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     didDIDPayload,
			//create
			PreviousTxid: previousTxid,
			//update
			//PreviousTxid:  "af1f64a6d00a79c2b82919805ee21de9bc3782168a60175f0ea5509c81192111",
		},
		Payload: base64url.EncodeToString(info.GetData()),
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: id + VMKey, //primary
		},
		DIDDoc: info,
	}
	//payload proof sign create and verify
	sign, _ := crypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}


//decalre verifiableCredential
func (s *PayloadGenerator)getPayloadDIDInfoChangeDoc_customterDID_verifiableCredential(id string, didDIDPayload string, docBytes []byte, privateKey1Str string, publicKey1Str string,
	privateKey2Str []string, publicKey2Str []string, VMKey string, privateKeyVerCreStr string, publicKeyVerCrStr string) *did.DIDPayload {
	//pBytes := getDIDPayloadBytes(id)
	//	var infoProofArray = []*did.DocProof{}
	//	var infoProofStr string
	privateKey1 := base58.Decode(privateKey1Str)
	//	privateKey2 := base58.Decode(privateKey2Str)
	fmt.Println(" docBytes  before chg", string(docBytes))
	//	info := new(did.DIDDoc_customerDID)
	verifiableCredentialInfo := new(did.VerifiableCredentialDoc)
	json.Unmarshal(docBytes, verifiableCredentialInfo)

	//	sortDocSlice_customerDID(info)
	///////////////////////////////////////////
	//doc proof sign create and verify
	{
		//credential proof sign and verify
		/////////////////////////////////////VerifiableCredential签名
		fmt.Println("VerifiableCredential ", "privateKeyVerCreStr", privateKeyVerCreStr)
		fmt.Println("VerifiableCredential data ", string(verifiableCredentialInfo.VerifiableCredentialData.GetData()))
		privateKeyVerCre := base58.Decode(privateKeyVerCreStr)
		signVerCre, _ := crypto.Sign(privateKeyVerCre, verifiableCredentialInfo.VerifiableCredentialData.GetData())
		verifiableCredentialInfo.Proof.Signature = base64url.EncodeToString(signVerCre)
		fmt.Println("VerifiableCredential Signature ", verifiableCredentialInfo.Proof.Signature)
		fmt.Println("VerifiableCredential publicKeyVerCrStr[i]", publicKeyVerCrStr)
		publickey := base58.Decode(publicKeyVerCrStr)
		pubkey, err := crypto.DecodePoint(publickey)
		err = crypto.Verify(*pubkey, verifiableCredentialInfo.VerifiableCredentialData.GetData(), signVerCre)
		fmt.Println("getPayloadDIDInfo VerifiableCredential 1111", err)
	}
	fmt.Println(" docBytes after chg", string(verifiableCredentialInfo.GetData()))

	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/credential/1.0",
			Operation:     didDIDPayload,
			//create
			PreviousTxid: "",
			//update
			//PreviousTxid:  "7fd1a3aa97756f07436527f6e5b08a1f986133f5a6e713342f829c7e090573c3",
		},
		Payload: base64url.EncodeToString(verifiableCredentialInfo.GetData()),
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: id + VMKey, //primary
		},
		CredentialDoc: verifiableCredentialInfo,
	}
	//payload proof sign create and verify
	sign, _ := crypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}

//revoke verifiableCredential
func (s *PayloadGenerator)getPayloadDIDInfoChangeDoc_customterDID_verifiableCredential_Revoke(id string, didDIDPayload string, privateKey1Str string, publicKey1Str string, VMKey string, verifiableCredentialID string) *did.DIDPayload {

	privateKey1 := base58.Decode(privateKey1Str)
	publicKey1 := base58.Decode(publicKey1Str)

	fmt.Println(" header payload privateKey1:", string(privateKey1))
	fmt.Println(" header payload publicKey1:", string(publicKey1))

	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/credential/1.0",
			Operation:     didDIDPayload,
			//create
			PreviousTxid: "",
			//update
			//PreviousTxid:  "7fd1a3aa97756f07436527f6e5b08a1f986133f5a6e713342f829c7e090573c3",
		},
		Payload: verifiableCredentialID,
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: id + VMKey, //primary
		},
	}
	//payload proof sign create and verify
	sign, _ := crypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}


func (s *PayloadGenerator)getPayloadDIDInfoChangeDoc_Deactive(id string, didDIDPayload string, docBytes []byte, privateKey1Str, publicKey1Str,
	privateKey2Str, publicKey2Str, VMKey string, privateKeyVerCreStr, publicKeyVerCrStr []string) *did.DIDPayload {
	//pBytes := getDIDPayloadBytes(id)
	privateKey1 := base58.Decode(privateKey1Str)
	privateKey2 := base58.Decode(privateKey2Str)
	fmt.Println(" docBytes  before chg", string(docBytes))
	info := new(did.DIDDoc)
	json.Unmarshal(docBytes, info)

	sortDocSlice(info)
	///////////////////////////////////////////
	//doc proof sign create and verify

	{
		//credential proof sign and verify
		/////////////////////////////////////
		for i, v := range info.DIDPayloadData.VerifiableCredential {
			fmt.Println("VerifiableCredential ", i, "privateKeyVerCreStr", privateKeyVerCreStr[i])
			fmt.Println("VerifiableCredential data ", string(v.VerifiableCredentialData.GetData()))
			privateKeyVerCre := base58.Decode(privateKeyVerCreStr[i])
			signVerCre, _ := crypto.Sign(privateKeyVerCre, v.VerifiableCredentialData.GetData())
			info.DIDPayloadData.VerifiableCredential[i].Proof.Signature = base64url.EncodeToString(signVerCre)
			fmt.Println("VerifiableCredential Signature ", info.DIDPayloadData.VerifiableCredential[i].Proof.Signature)
			fmt.Println("VerifiableCredential publicKeyVerCrStr[i]", publicKeyVerCrStr[i])
			publickey := base58.Decode(publicKeyVerCrStr[i])
			pubkey, err := crypto.DecodePoint(publickey)
			err = crypto.Verify(*pubkey, v.VerifiableCredentialData.GetData(), signVerCre)
			fmt.Println("getPayloadDIDInfo VerifiableCredential 1111", err)

		}

		/////////////////////////////////
		sign, _ := crypto.Sign(privateKey2, info.DIDPayloadData.GetData())
		docProof := &did.DocProof{}
		if err := Unmarshal(info.Proof, docProof); err != nil {
			panic("error should not be here")
		}
		docProof.SignatureValue = base64url.EncodeToString(sign)
		publickey := base58.Decode(publicKey2Str)
		pubkey, err := crypto.DecodePoint(publickey)
		fmt.Println(err)
		//fmt.Println("1111111 public key ", "kTYQhMtoimm9wV3vy4q9EVy4Z1WxRqxhvngztdGo1Dmc")
		//fmt.Println("1111111 SignatureValue ", docProof.SignatureValue)
		//fmt.Println("1111111 info.GetData()", string(info.GetData()))
		//info.Proof = docProof
		err = crypto.Verify(*pubkey, info.DIDPayloadData.GetData(), sign)
		fmt.Println("getPayloadDIDInfo Verify 1111", err)
		info.Proof = docProof
	}
	fmt.Println(" docBytes after chg", string(info.GetData()))

	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     didDIDPayload,
			//PreviousTxid:  "",
			//
		},
		//Payload: base64url.EncodeToString(info.GetData()),
		Payload: id,
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: id + VMKey, //primary
		},
		DIDDoc: info,
	}
	//payload proof sign create and verify
	sign, _ := crypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}