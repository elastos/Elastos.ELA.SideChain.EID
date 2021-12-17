package did

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/elastos/Elastos.ELA/common"
)

// payload in DID transaction payload
type DIDDoc struct {
	*DIDPayloadData
	Proof interface{} `json:"proof,omitempty"`
}

func (c *DIDDoc) GetData() []byte {
	data, err := MarshalDocData(c)
	if err != nil {
		return nil
	}
	return data
}

type VerifiableCredentialDoc struct {
	*VerifiableCredentialData
	Proof CredentialProof `json:"proof,omitempty"`
}

func (p *VerifiableCredentialDoc) CompleteCompact(did string) {
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
	Context 		  []string    `json:"@context,omitempty"`
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

type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

type DIDPayloadData struct {
	Context 			 []string               `json:"@context,omitempty"`
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

type ControllerSlice []interface{}

func (s ControllerSlice) Len() int {
	return len(s)
}
func (s ControllerSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s ControllerSlice) Less(i, j int) bool {
	result := false
	serviceI := s[i].(string)
	serviceJ := s[j].(string)
	if strings.Compare(serviceI, serviceJ) < 0 {
		result = true
	}
	return result
}


type ServiceSlice []interface{}

func (s ServiceSlice) Len() int {
	return len(s)
}
func (s ServiceSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s ServiceSlice) Less(i, j int) bool {
	result := false
	serviceI := s[i].(map[string]interface{})
	serviceJ := s[j].(map[string]interface{})
	if strings.Compare(serviceI["id"].(string), serviceJ["id"].(string)) < 0 {
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
	data, err := MarshalDIDPayloadData(c)
	if err != nil {
		return nil
	}
	return data
}

// public keys of payload in DID transaction payload
type DIDPublicKeyInfo struct {
	ID              string `json:"id"`
	Type            string `json:"type,omitempty"`
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
