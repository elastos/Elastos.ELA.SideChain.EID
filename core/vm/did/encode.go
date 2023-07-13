package did

import (
	"github.com/elastos/Elastos.ELA.SideChain.EID/accounts/abi"
)

func EncodeVerifiableCredentialData(p *VerifiableCredentialData) ([]byte, error) {

	String, _ := abi.NewType("string", "string", nil)

	arguments := make([]abi.Argument, 0)
	IDKey := abi.Argument{Name: "id", Type: String}
	arguments = append(arguments, IDKey)

	IssuerKey := abi.Argument{Name: "issuer", Type: String}
	arguments = append(arguments, IssuerKey)

	IssuanceDateKey := abi.Argument{Name: "issuanceDate", Type: String}
	arguments = append(arguments, IssuanceDateKey)

	ExpirationDateKey := abi.Argument{Name: "ExpirationDate", Type: String}
	arguments = append(arguments, ExpirationDateKey)

	m := abi.Method{Inputs: arguments}
	ret, err := m.Inputs.Pack(p.ID, p.Issuer, p.IssuanceDate, p.ExpirationDate)
	if err != nil {
		return ret, err
	}
	return ret, nil
}
