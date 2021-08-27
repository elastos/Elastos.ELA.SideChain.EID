package did

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/elastos/Elastos.ELA/common"
)

// payload in DID transaction payload
type DIDDoc struct {
	*DIDPayloadData
	Proof interface{} `json:"proof,omitempty"`
}

type VerifiableCredentialDoc struct {
	*VerifiableCredential `json:"verifiableCredential,omitempty"`
}

type VerifiableCredential struct {
	*VerifiableCredentialData
	Proof CredentialProof `json:"proof,omitempty"`
}

type VerifiableCredentialTxData struct {
	TXID      string     `json:"txid"`
	Timestamp string     `json:"timestamp"`
	Operation DIDPayload `json:"operation"`
}

func (p *VerifiableCredential) GetDIDProofInfo() *CredentialProof {
	return &p.Proof
}

func (p *VerifiableCredential) CompleteCompact(did string) {
	if IsCompact(p.Issuer) {
		p.Issuer = did + p.Issuer
	}
	if IsCompact(p.ID) {
		p.ID = did + p.ID
	}

	creSub := p.CredentialSubject.(map[string]interface{})
	realIssuer := ""
	for k, v := range creSub {
		if k == ID_STRING {
			realIssuer = v.(string)
			break
		}
	}
	if realIssuer == "" {
		creSub[ID_STRING] = did
	}
}

type VerifiableCredentialData struct {
	ID                string      `json:"id"`
	Type              []string    `json:"type,omitempty"`
	Issuer            string      `json:"issuer,omitempty"`
	IssuanceDate      string      `json:"issuanceDate,omitempty"`
	ExpirationDate    string      `json:"expirationDate,omitempty"`
	CredentialSubject interface{} `json:"credentialSubject,omitempty"`
}

func (p *VerifiableCredentialData) GetData() []byte {
	buf := new(bytes.Buffer)
	err := MarshalVerifiableCredentialData(p, buf)
	if err != nil {
		return nil
	}
	return buf.Bytes()
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
	isd, err := json.Marshal(p.Issuer)
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
	exp, err := json.Marshal(p.Issuer)
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
		} else {
			buf.WriteRune('}')
		}
	}

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

type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
	//user define extra property
	//ExtraProperty interface{} `json:"extraProperty,omitempty"`
}

type DIDPayloadData struct {
	ID                   string                 `json:"id"`
	Controller           interface{}            `json:"controller,omitempty"`
	MultiSig             string                 `json:"multisig,omitempty"`
	PublicKey            []DIDPublicKeyInfo     `json:"publicKey,omitempty"`
	Authentication       []interface{}          `json:"authentication,omitempty"`
	Authorization        []interface{}          `json:"authorization,omitempty"`
	VerifiableCredential []VerifiableCredential `json:"verifiableCredential,omitempty"`
	Service              []interface{}          `json:"service,omitempty"`
	Expires              string                 `json:"expires"`
}

type PublicKeysSlice []DIDPublicKeyInfo

func (a PublicKeysSlice) Len() int {
	return len(a)
}
func (a PublicKeysSlice) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}
func (a PublicKeysSlice) Less(i, j int) bool {
	result := false
	if strings.Compare(a[i].ID, a[j].ID) < 0 {
		result = true
	}
	return result
}

type ServiceSlice []Service

func (s ServiceSlice) Len() int {
	return len(s)
}
func (s ServiceSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s ServiceSlice) Less(i, j int) bool {
	result := false
	if strings.Compare(s[i].ID, s[j].ID) < 0 {
		result = true
	}
	return result
}

type VerifiableCredentialSlice []VerifiableCredential

func (v VerifiableCredentialSlice) Len() int {
	return len(v)
}
func (v VerifiableCredentialSlice) Swap(i, j int) {
	v[i], v[j] = v[j], v[i]
}
func (v VerifiableCredentialSlice) Less(i, j int) bool {
	result := false
	if strings.Compare(v[i].ID, v[j].ID) < 0 {
		result = true
	}
	return result
}

func (p *DIDPayloadData) MarshalJSON() ([]byte, error) {
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
			if err = MarshalVerifiableCredentialData(vc.VerifiableCredentialData, buf); err != nil {
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

	fmt.Println(buf.String())
	return buf.Bytes(), nil
}

func writeKey(buf *bytes.Buffer, key string) error {
	sig, err := json.Marshal(key)
	if err != nil {
		return err
	}
	buf.Write(sig)
	buf.WriteRune(':')
	return nil
}

func (c *DIDPayloadData) GetData() []byte {
	data, err := c.MarshalJSON()
	if err != nil {
		return nil
	}
	return data
}

// public keys of payload in DID transaction payload
type DIDPublicKeyInfo struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	Controller      string `json:"controller"`
	PublicKeyBase58 string `json:"publicKeyBase58"`
}

func (p *DIDPublicKeyInfo) Serialize(w io.Writer, version byte) error {
	if err := common.WriteVarString(w, p.ID); err != nil {
		return errors.New("[DIDPublicKeyInfo], ID serialize failed.")
	}
	if err := common.WriteVarString(w, p.Type); err != nil {
		return errors.New("[DIDPublicKeyInfo], Type serialize failed.")
	}
	if err := common.WriteVarString(w, p.Controller); err != nil {
		return errors.New("[DIDPublicKeyInfo], Controller serialize failed.")
	}
	if err := common.WriteVarString(w, p.PublicKeyBase58); err != nil {
		return errors.New("[DIDPublicKeyInfo], PublicKeyBase58 serialize failed.")
	}

	return nil
}

func (p *DIDPublicKeyInfo) Deserialize(r io.Reader, version byte) error {
	id, err := common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDPublicKeyInfo], ID deserialize failed")
	}
	p.ID = id

	typePkInfo, err := common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDPublicKeyInfo], Type deserialize failed")
	}
	p.Type = typePkInfo

	controller, err := common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDPublicKeyInfo], Controller deserialize failed")
	}
	p.Controller = controller

	pkBase58, err := common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDPublicKeyInfo], PublicKeyBase58 deserialize failed")
	}
	p.PublicKeyBase58 = pkBase58

	return nil
}

func IsCompact(target string) bool {
	if !strings.HasPrefix(target, DID_ELASTOS_PREFIX) {
		return true
	}
	return false
}
