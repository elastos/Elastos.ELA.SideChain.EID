package did

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
)

var NotEscHTML bool

func JSONMarshal(t interface{}) ([]byte, error) {
	data, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}
	if NotEscHTML {
		return notEscapeHTML(data), nil
	}
	return data, nil
}

func notEscapeHTML(data []byte) []byte {
	data = bytes.Replace(data, []byte("\\u0026"), []byte("&"), -1)
	data = bytes.Replace(data, []byte("\\u003c"), []byte("<"), -1)
	data = bytes.Replace(data, []byte("\\u003e"), []byte(">"), -1)
	return data
}

func MarshalDIDPayloadData(p *DIDPayloadData) ([]byte, error) {
	buf := NewNFCBuffer()
	buf.WriteString("{")

	//context
	contextCount := len(p.Context)
	if contextCount != 0 {
		err := buf.WriteKey("@context")
		if err != nil {
			return nil, err
		}
		pks, err := JSONMarshal(p.Context)
		if err != nil {
			return nil, err
		}
		nfcPKS := ToNFCBytes(pks)
		buf.Write(nfcPKS)
		buf.WriteString(",")
	}

	// ID
	err := buf.WriteKey("id")
	if err != nil {
		return nil, err
	}
	idv, err := JSONMarshal(p.ID)
	if err != nil {
		return nil, err
	}
	buf.Write(idv)
	buf.WriteString(",")

	// Controller
	if p.Controller != nil {
		err := buf.WriteKey("controller")
		if err != nil {
			return nil, err
		}

		idv, err := JSONMarshal(p.Controller)
		if err != nil {
			return nil, err
		}
		buf.Write(idv)
		buf.WriteString(",")
	}

	// MultiSig
	if p.MultiSig != "" {
		err := buf.WriteKey("multisig")
		if err != nil {
			return nil, err
		}
		sigv, err := JSONMarshal(p.MultiSig)
		if err != nil {
			return nil, err
		}
		buf.Write(sigv)
		buf.WriteString(",")
	}

	// Publickey
	count := len(p.PublicKey)
	if count != 0 {
		err := buf.WriteKey("publicKey")
		if err != nil {
			return nil, err
		}
		pks, err := JSONMarshal(p.PublicKey)
		if err != nil {
			return nil, err
		}
		buf.Write(pks)
		buf.WriteString(",")
	}

	// Authentication
	count = len(p.Authentication)
	if count != 0 {
		err = buf.WriteKey("authentication")
		if err != nil {
			return nil, err
		}
		buf.WriteString("[")
		for i, authen := range p.Authentication {
			if err = MarshalAuthentication(authen, buf); err != nil {
				return nil, err
			}
			if i != count-1 {
				buf.WriteString(",")
			}
		}
		buf.WriteString("]")
		buf.WriteString(",")
	}

	// Authorization
	count = len(p.Authorization)
	if count != 0 {
		err := buf.WriteKey("authorization")
		if err != nil {
			return nil, err
		}
		buf.WriteString("[")
		for i, vc := range p.Authorization {
			if err = MarshalAuthentication(vc, buf); err != nil {
				return nil, err
			}
			if i != count-1 {
				buf.WriteString(",")
			}
		}
		buf.WriteString("]")
		buf.WriteString(",")
	}

	// VerifiableCredential
	count = len(p.VerifiableCredential)
	if count != 0 {
		err := buf.WriteKey("verifiableCredential")
		if err != nil {
			return nil, err
		}
		buf.WriteString("[")
		for i, vc := range p.VerifiableCredential {
			if err = MarshalVerifiableCredential(vc, buf); err != nil {
				return nil, err
			}
			if i != count-1 {
				buf.WriteString(",")
			}
		}
		buf.WriteString("]")
		buf.WriteString(",")
	}

	// Servie
	count = len(p.Service)
	if count != 0 {
		if err := buf.WriteKey("service"); err != nil {
			return nil, err
		}
		buf.WriteString("[")
		for i, se := range p.Service {
			if err := MarshalService(se, buf); err != nil {
				return nil, err
			}
			if i != count-1 {
				buf.WriteString(",")
			}
		}
		buf.WriteString("]")
		buf.WriteString(",")
	}

	// Expires
	if p.Expires != "" {
		if err := buf.WriteKey("expires"); err != nil {
			return nil, err
		}
		sigv, err := JSONMarshal(p.Expires)
		if err != nil {
			return nil, err
		}
		buf.Write(sigv)
	}

	buf.WriteString("}")

	return buf.Bytes(), nil
}

func MarshalDocData(doc *DIDDoc) ([]byte, error) {
	p := doc.DIDPayloadData
	buf := NewNFCBuffer()
	buf.WriteString("{")

	//context
	contextCount := len(p.Context)
	if contextCount != 0 {
		err := buf.WriteKey("@context")
		if err != nil {
			return nil, err
		}
		pks, err := JSONMarshal(p.Context)
		if err != nil {
			return nil, err
		}
		buf.Write(pks)
		buf.WriteString(",")
	}
	// ID
	err := buf.WriteKey("id")
	if err != nil {
		return nil, err
	}
	idv, err := JSONMarshal(p.ID)
	if err != nil {
		return nil, err
	}
	buf.Write(idv)
	buf.WriteString(",")

	// Controller
	if p.Controller != nil {
		err := buf.WriteKey("controller")
		if err != nil {
			return nil, err
		}

		idv, err := JSONMarshal(p.Controller)
		if err != nil {
			return nil, err
		}
		buf.Write(idv)

		buf.WriteString(",")
	}

	// MultiSig
	if p.MultiSig != "" {
		err := buf.WriteKey("multisig")
		if err != nil {
			return nil, err
		}
		sigv, err := JSONMarshal(p.MultiSig)
		if err != nil {
			return nil, err
		}
		buf.Write(sigv)
		buf.WriteString(",")
	}

	// Publickey
	count := len(p.PublicKey)
	if count != 0 {
		err := buf.WriteKey("publicKey")
		if err != nil {
			return nil, err
		}
		pks, err := JSONMarshal(p.PublicKey)
		if err != nil {
			return nil, err
		}
		buf.Write(pks)
		buf.WriteString(",")
	}

	// Authentication
	count = len(p.Authentication)
	if count != 0 {
		err = buf.WriteKey("authentication")
		if err != nil {
			return nil, err
		}
		buf.WriteString("[")
		for i, authen := range p.Authentication {
			if err = MarshalAuthentication(authen, buf); err != nil {
				return nil, err
			}
			if i != count-1 {
				buf.WriteString(",")
			}
		}
		buf.WriteString("]")
		buf.WriteString(",")
	}

	// Authorization
	count = len(p.Authorization)
	if count != 0 {
		err := buf.WriteKey("authorization")
		if err != nil {
			return nil, err
		}
		buf.WriteString("[")
		for i, vc := range p.Authorization {
			if err = MarshalAuthentication(vc, buf); err != nil {
				return nil, err
			}
			if i != count-1 {
				buf.WriteString(",")
			}
		}
		buf.WriteString("]")
		buf.WriteString(",")
	}

	// VerifiableCredential
	count = len(p.VerifiableCredential)
	if count != 0 {
		err := buf.WriteKey("verifiableCredential")
		if err != nil {
			return nil, err
		}
		buf.WriteString("[")
		for i, vc := range p.VerifiableCredential {
			if err = MarshalVerifiableCredential(vc, buf); err != nil {
				return nil, err
			}
			if i != count-1 {
				buf.WriteString(",")
			}
		}
		buf.WriteString("]")
		buf.WriteString(",")
	}

	// Servie
	count = len(p.Service)
	if count != 0 {
		if err := buf.WriteKey("service"); err != nil {
			return nil, err
		}
		buf.WriteString("[")
		for i, se := range p.Service {
			if err := MarshalService(se, buf); err != nil {
				return nil, err
			}
			if i != count-1 {
				buf.WriteString(",")
			}
		}
		buf.WriteString("]")
		buf.WriteString(",")
	}

	// Expires
	if p.Expires != "" {
		if err := buf.WriteKey("expires"); err != nil {
			return nil, err
		}
		sigv, err := JSONMarshal(p.Expires)
		if err != nil {
			return nil, err
		}
		buf.Write(sigv)
	}

	buf.WriteString(",")
	err = buf.WriteKey("proof")
	if err != nil {
		return nil, err
	}
	pf, err := JSONMarshal(doc.Proof)
	if err != nil {
		return nil, err
	}
	buf.Write(pf)
	buf.WriteString("}")

	return buf.Bytes(), nil
}

func MarshalVerifiableCredential(p VerifiableCredential, buf *NFCBuffer) error {
	buf.WriteString("{")
	//context
	contextCount := len(p.Context)
	if contextCount != 0 {
		err := buf.WriteKey("@context")
		if err != nil {
			return err
		}
		pks, err := JSONMarshal(p.Context)
		if err != nil {
			return err
		}
		buf.Write(pks)
		buf.WriteString(",")
	}
	// ID
	err := buf.WriteKey("id")
	if err != nil {
		return err
	}
	idv, err := JSONMarshal(p.ID)
	if err != nil {
		return err
	}
	buf.Write(idv)
	buf.WriteString(",")

	// Type
	count := len(p.Type)
	if count != 0 {
		err := buf.WriteKey("type")
		if err != nil {
			return err
		}
		tpe, err := JSONMarshal(p.Type)
		if err != nil {
			return err
		}
		buf.Write(tpe)
		buf.WriteString(",")
	}

	// Issuer
	if err = buf.WriteKey("issuer"); err != nil {
		return err
	}
	ise, err := JSONMarshal(p.Issuer)
	if err != nil {
		return err
	}
	buf.Write(ise)
	buf.WriteString(",")

	// IssuanceDate
	err = buf.WriteKey("issuanceDate")
	if err != nil {
		return err
	}
	isd, err := JSONMarshal(p.IssuanceDate)
	if err != nil {
		return err
	}
	buf.Write(isd)
	buf.WriteString(",")

	// ExpirationDate if not empty str
	if p.ExpirationDate != "" {
		err = buf.WriteKey("expirationDate")
		if err != nil {
			return err
		}
		exp, err := JSONMarshal(p.ExpirationDate)
		if err != nil {
			return err
		}
		buf.Write(exp)
		buf.WriteString(",")
	}

	// CredentialSubject
	err = buf.WriteKey("credentialSubject")
	if err != nil {
		return err
	}
	err = MarshalCredentialSubject(p.CredentialSubject, buf)
	if err != nil {
		return err
	}
	buf.WriteString(",")

	// proof
	err = buf.WriteKey("proof")
	if err != nil {
		return err
	}
	pf, err := JSONMarshal(p.Proof)
	if err != nil {
		return err
	}
	buf.Write(pf)

	buf.WriteString("}")
	return nil
}

func MarshalVerifiableCredentialData(p *VerifiableCredentialData, buf *NFCBuffer) error {
	buf.WriteString("{")
	//context
	contextCount := len(p.Context)
	if contextCount != 0 {
		err := buf.WriteKey("@context")
		if err != nil {
			return err
		}
		pks, err := JSONMarshal(p.Context)
		if err != nil {
			return err
		}
		buf.Write(pks)
		buf.WriteString(",")
	}
	// ID
	err := buf.WriteKey("id")
	if err != nil {
		return err
	}
	idv, err := JSONMarshal(p.ID)
	if err != nil {
		return err
	}
	buf.Write(idv)
	buf.WriteString(",")

	// Type
	count := len(p.Type)
	if count != 0 {
		err := buf.WriteKey("type")
		if err != nil {
			return err
		}
		tpe, err := JSONMarshal(p.Type)
		if err != nil {
			return err
		}
		buf.Write(tpe)
		buf.WriteString(",")
	}

	// Issuer
	if err = buf.WriteKey("issuer"); err != nil {
		return err
	}
	ise, err := JSONMarshal(p.Issuer)
	if err != nil {
		return err
	}
	buf.Write(ise)
	buf.WriteString(",")

	// IssuanceDate
	err = buf.WriteKey("issuanceDate")
	if err != nil {
		return err
	}
	isd, err := JSONMarshal(p.IssuanceDate)
	if err != nil {
		return err
	}
	buf.Write(isd)
	buf.WriteString(",")

	// ExpirationDate
	if p.ExpirationDate != "" {
		err = buf.WriteKey("expirationDate")
		if err != nil {
			return err
		}
		exp, err := JSONMarshal(p.ExpirationDate)
		if err != nil {
			return err
		}
		buf.Write(exp)
		buf.WriteString(",")
	}
	// CredentialSubject
	err = buf.WriteKey("credentialSubject")
	if err != nil {
		return err
	}
	err = MarshalCredentialSubject(p.CredentialSubject, buf)
	if err != nil {
		return err
	}

	buf.WriteString("}")
	return nil
}

func MarshalCredentialSubject(credentialSubject interface{}, buf *NFCBuffer) error {
	creSub := credentialSubject.(map[string]interface{})
	_, ok := creSub["id"]
	if !ok {
		return errors.New("not found id in credential kvData")
	}

	type subject struct {
		key   string
		value interface{}
	}
	sortedData := make([]subject, 0)
	for k, v := range creSub {
		sortedData = append(sortedData, subject{k, v})
	}

	sort.Slice(sortedData, func(i, j int) bool {
		if sortedData[i].key == "id" {
			return true
		}
		if sortedData[j].key == "id" {
			return false
		}

		return sortedData[i].key < sortedData[j].key
	})

	l := len(sortedData)
	buf.WriteString("{")
	for i, data := range sortedData {
		err := buf.WriteKey(data.key)
		if err != nil {
			return err
		}
		//JSONMarshal
		idv, err := JSONMarshal(data.value)
		//idv, err := JSONMarshal(data.value)
		if err != nil {
			return err
		}
		buf.Write(idv)

		if i != l-1 {
			buf.WriteString(",")
		}
	}
	buf.WriteString("}")

	return nil
}

func MarshalService(service interface{}, buf *NFCBuffer) error {
	ser := service.(map[string]interface{})
	if _, ok := ser["id"]; !ok {
		return errors.New("not found id in service")
	}
	if _, ok := ser["type"]; !ok {
		return errors.New("not found type in service")
	}
	if _, ok := ser["serviceEndpoint"]; !ok {
		return errors.New("not found serviceEndpoint in service")
	}

	type kvData struct {
		key   string
		value interface{}
	}
	sortedData := make([]kvData, 0)
	for k, v := range ser {
		sortedData = append(sortedData, kvData{k, v})
	}

	sort.Slice(sortedData, func(i, j int) bool {
		if sortedData[i].key == "id" {
			return true
		}
		if sortedData[j].key == "id" {
			return false
		}
		if sortedData[i].key == "type" {
			return true
		}
		if sortedData[j].key == "type" {
			return false
		}
		if sortedData[i].key == "serviceEndpoint" {
			return true
		}
		if sortedData[j].key == "serviceEndpoint" {
			return false
		}

		return sortedData[i].key < sortedData[j].key
	})

	l := len(sortedData)
	buf.WriteString("{")
	for i, data := range sortedData {
		err := buf.WriteKey(data.key)
		if err != nil {
			return err
		}
		//
		idv, err := JSONMarshal(data.value)
		//idv, err := JSONMarshal(data.value)
		if err != nil {
			return err
		}
		buf.Write(idv)

		if i != l-1 {
			buf.WriteString(",")
		} else {
			buf.WriteString("}")
		}
	}

	return nil
}

func MarshalAuthentication(auth interface{}, buf *NFCBuffer) error {

	switch auth.(type) {
	case string:
		keyString := auth.(string)
		isd, err := JSONMarshal(keyString)
		if err != nil {
			return err
		}
		buf.Write(isd)
	case map[string]interface{}:
		data, err := JSONMarshal(auth)
		if err != nil {
			return err
		}
		didPublicKeyInfo := new(DIDPublicKeyInfo)
		err = json.Unmarshal(data, didPublicKeyInfo)
		if err != nil {
			return err
		}
		isd, err := JSONMarshal(didPublicKeyInfo)
		if err != nil {
			return err
		}
		buf.Write(isd)
	default:
		return errors.New("[ID MarshalAuthentication] invalid  auth.(type)")
	}

	return nil
}
