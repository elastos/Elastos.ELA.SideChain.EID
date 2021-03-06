package payload

import (
	"bytes"
	"io"

	"github.com/elastos/Elastos.ELA/common"
)

const CustomIDResultVersion byte = 0x00

type RecordProposalResult struct {
	ProposalResults []ProposalResult
}

type ProposalResult struct {
	ProposalHash common.Uint256
	ProposalType CRCProposalType
	Result       bool
}

func (p *ProposalResult) Serialize(w io.Writer, version byte) error {
	if err := p.ProposalHash.Serialize(w); err != nil {
		return err
	}

	if err := common.WriteUint16(w, uint16(p.ProposalType)); err != nil {
		return err
	}
	if err := common.WriteElements(w, p.Result); err != nil {
		return err
	}
	return nil
}

func (p *ProposalResult) Deserialize(r io.Reader, version byte) error {
	if err := p.ProposalHash.Deserialize(r); err != nil {
		return err
	}
	//var proposalType uint16
	proposalType, err := common.ReadUint16(r)
	if err != nil {
		return err
	}
	p.ProposalType = CRCProposalType(proposalType)
	if err := common.ReadElements(r, &p.Result); err != nil {
		return err
	}
	return nil
}

func (p *RecordProposalResult) Data(version byte) []byte {
	buf := new(bytes.Buffer)
	if err := p.Serialize(buf, version); err != nil {
		return []byte{0}
	}
	return buf.Bytes()
}

func (p *RecordProposalResult) Serialize(w io.Writer, version byte) error {
	err := p.SerializeUnsigned(w, version)
	if err != nil {
		return err
	}
	return nil
}

func (p *RecordProposalResult) SerializeUnsigned(w io.Writer, version byte) error {
	if err := common.WriteVarUint(w, uint64(len(p.ProposalResults))); err != nil {
		return err
	}
	for _, v := range p.ProposalResults {
		if err := v.Serialize(w, version); err != nil {
			return err
		}
	}
	return nil
}

func (p *RecordProposalResult) Deserialize(r io.Reader, version byte) error {
	err := p.DeserializeUnsigned(r, version)
	if err != nil {
		return err
	}
	return nil
}

func (p *RecordProposalResult) DeserializeUnsigned(r io.Reader, version byte) error {
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	for i := uint64(0); i < count; i++ {
		var result ProposalResult
		if err = result.Deserialize(r, version); err != nil {
			return err
		}
		p.ProposalResults = append(p.ProposalResults, result)
	}
	return nil
}
