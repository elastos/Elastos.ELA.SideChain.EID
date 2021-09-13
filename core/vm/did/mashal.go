package did

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
)

func MarshalDIDPayloadData(p *DIDPayloadData) ([]byte, error) {
	var b []byte
	buf := bytes.NewBuffer(b)
	buf.WriteRune('{')

	// ID
	err := writeKey(buf, "id")
	if err != nil {
		return nil, err
	}
	idv, err := json.Marshal(p.ID)
	if err != nil {
		return nil, err
	}
	buf.Write(idv)
	buf.WriteRune(',')

	// Controller
	if p.Controller != nil {
		err := writeKey(buf, "controller")
		if err != nil {
			return nil, err
		}

		//if id, ok := p.Controller.(string); ok {
		idv, err := json.Marshal(p.Controller)
		if err != nil {
			return nil, err
		}
		buf.Write(idv)
		//}

		buf.WriteRune(',')
	}

	// MultiSig
	if p.MultiSig != "" {
		err := writeKey(buf, "multisig")
		if err != nil {
			return nil, err
		}
		sigv, err := json.Marshal(p.MultiSig)
		if err != nil {
			return nil, err
		}
		buf.Write(sigv)
		buf.WriteRune(',')
	}

	// Publickey
	count := len(p.PublicKey)
	if count != 0 {
		err := writeKey(buf, "publicKey")
		if err != nil {
			return nil, err
		}
		pks, err := json.Marshal(p.PublicKey)
		if err != nil {
			return nil, err
		}
		buf.Write(pks)
		buf.WriteRune(',')
	}

	// Authentication
	count = len(p.Authentication)
	if count != 0 {
		err := writeKey(buf, "authentication")
		if err != nil {
			return nil, err
		}
		ath, err := json.Marshal(p.Authentication)
		if err != nil {
			return nil, err
		}
		buf.Write(ath)
		buf.WriteRune(',')
	}

	// Authorization
	count = len(p.Authorization)
	if count != 0 {
		err := writeKey(buf, "authorization")
		if err != nil {
			return nil, err
		}
		ath, err := json.Marshal(p.Authorization)
		if err != nil {
			return nil, err
		}
		buf.Write(ath)
		buf.WriteRune(',')
	}

	// VerifiableCredential
	count = len(p.VerifiableCredential)
	if count != 0 {
		err := writeKey(buf, "verifiableCredential")
		if err != nil {
			return nil, err
		}
		buf.WriteRune('[')
		for i, vc := range p.VerifiableCredential {
			if err = MarshalVerifiableCredential(vc, buf); err != nil {
				return nil, err
			}
			if i != count-1 {
				buf.WriteRune(',')
			}
		}
		buf.WriteRune(']')
		buf.WriteRune(',')
	}

	// Servie
	count = len(p.Service)
	if count != 0 {
		if err := writeKey(buf, "service"); err != nil {
			return nil, err
		}
		buf.WriteRune('[')
		for i, se := range p.Service {
			if err := MarshalService(se, buf); err != nil {
				return nil, err
			}
			if i != count-1 {
				buf.WriteRune(',')
			}
		}
		buf.WriteRune(']')
		buf.WriteRune(',')
	}

	// Expires
	if p.Expires != "" {
		if err := writeKey(buf, "expires"); err != nil {
			return nil, err
		}
		sigv, err := json.Marshal(p.Expires)
		if err != nil {
			return nil, err
		}
		buf.Write(sigv)
	}

	buf.WriteRune('}')

	return buf.Bytes(), nil
}

func MarshalVerifiableCredential(p VerifiableCredential, buf *bytes.Buffer) error {
	buf.WriteRune('{')

	// ID
	err := writeKey(buf, "id")
	if err != nil {
		return err
	}
	idv, err := json.Marshal(p.ID)
	if err != nil {
		return err
	}
	buf.Write(idv)
	buf.WriteRune(',')

	// Type
	count := len(p.Type)
	if count != 0 {
		err := writeKey(buf, "type")
		if err != nil {
			return err
		}
		tpe, err := json.Marshal(p.Type)
		if err != nil {
			return err
		}
		buf.Write(tpe)
		buf.WriteRune(',')
	}

	// Issuer
	if err = writeKey(buf, "issuer"); err != nil {
		return err
	}
	ise, err := json.Marshal(p.Issuer)
	if err != nil {
		return err
	}
	buf.Write(ise)
	buf.WriteRune(',')

	// IssuanceDate
	err = writeKey(buf, "issuanceDate")
	if err != nil {
		return err
	}
	isd, err := json.Marshal(p.IssuanceDate)
	if err != nil {
		return err
	}
	buf.Write(isd)
	buf.WriteRune(',')

	// ExpirationDate
	err = writeKey(buf, "expirationDate")
	if err != nil {
		return err
	}
	exp, err := json.Marshal(p.ExpirationDate)
	if err != nil {
		return err
	}
	buf.Write(exp)
	buf.WriteRune(',')

	// CredentialSubject
	err = writeKey(buf, "credentialSubject")
	if err != nil {
		return err
	}
	err = MarshalCredentialSubject(p.CredentialSubject, buf)
	if err != nil {
		return err
	}
	buf.WriteRune(',')

	// proof
	err = writeKey(buf, "proof")
	if err != nil {
		return err
	}
	pf, err := json.Marshal(p.Proof)
	if err != nil {
		return err
	}
	buf.Write(pf)

	buf.WriteRune('}')
	return nil
}

func MarshalVerifiableCredentialData(p *VerifiableCredentialData, buf *bytes.Buffer) error {
	buf.WriteRune('{')

	// ID
	err := writeKey(buf, "id")
	if err != nil {
		return err
	}
	idv, err := json.Marshal(p.ID)
	if err != nil {
		return err
	}
	buf.Write(idv)
	buf.WriteRune(',')

	// Type
	count := len(p.Type)
	if count != 0 {
		err := writeKey(buf, "type")
		if err != nil {
			return err
		}
		tpe, err := json.Marshal(p.Type)
		if err != nil {
			return err
		}
		buf.Write(tpe)
		buf.WriteRune(',')
	}

	// Issuer
	if err = writeKey(buf, "issuer"); err != nil {
		return err
	}
	ise, err := json.Marshal(p.Issuer)
	if err != nil {
		return err
	}
	buf.Write(ise)
	buf.WriteRune(',')

	// IssuanceDate
	err = writeKey(buf, "issuanceDate")
	if err != nil {
		return err
	}
	isd, err := json.Marshal(p.IssuanceDate)
	if err != nil {
		return err
	}
	buf.Write(isd)
	buf.WriteRune(',')

	// ExpirationDate
	err = writeKey(buf, "expirationDate")
	if err != nil {
		return err
	}
	exp, err := json.Marshal(p.ExpirationDate)
	if err != nil {
		return err
	}
	buf.Write(exp)
	buf.WriteRune(',')

	// CredentialSubject
	err = writeKey(buf, "credentialSubject")
	if err != nil {
		return err
	}
	err = MarshalCredentialSubject(p.CredentialSubject, buf)
	if err != nil {
		return err
	}

	buf.WriteRune('}')
	return nil
}

func MarshalCredentialSubject(credentialSubject interface{}, buf *bytes.Buffer) error {
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
	buf.WriteRune('{')
	for i, data := range sortedData {
		err := writeKey(buf, data.key)
		if err != nil {
			return err
		}
		idv, err := json.Marshal(data.value)
		if err != nil {
			return err
		}
		buf.Write(idv)

		if i != l-1 {
			buf.WriteRune(',')
		}
	}
	buf.WriteRune('}')

	return nil
}

func MarshalService(service interface{}, buf *bytes.Buffer) error {
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
	buf.WriteRune('{')
	for i, data := range sortedData {
		err := writeKey(buf, data.key)
		if err != nil {
			return err
		}
		idv, err := json.Marshal(data.value)
		if err != nil {
			return err
		}
		buf.Write(idv)

		if i != l-1 {
			buf.WriteRune(',')
		} else {
			buf.WriteRune('}')
		}
	}

	return nil
}
