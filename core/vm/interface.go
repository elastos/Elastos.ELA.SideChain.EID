// Copyright 2016 The Elastos.ELA.SideChain.EID Authors
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
	"math/big"

	"github.com/elastos/Elastos.ELA.SideChain.EID/common"
	"github.com/elastos/Elastos.ELA.SideChain.EID/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.EID/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.EID/params"

	elacom "github.com/elastos/Elastos.ELA/common"
)

// StateDB is an EVM database for full state querying.
type StateDB interface {
	CreateAccount(common.Address)

	SubBalance(common.Address, *big.Int)
	AddBalance(common.Address, *big.Int)
	GetBalance(common.Address) *big.Int

	GetNonce(common.Address) uint64
	SetNonce(common.Address, uint64)

	GetCodeHash(common.Address) common.Hash
	GetCode(common.Address) []byte
	SetCode(common.Address, []byte)
	GetCodeSize(common.Address) int

	AddRefund(uint64)
	SubRefund(uint64)
	GetRefund() uint64

	GetCommittedState(common.Address, common.Hash) common.Hash
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash)

	GetTransientState(addr common.Address, key common.Hash) common.Hash
	SetTransientState(addr common.Address, key, value common.Hash)

	Suicide(common.Address) bool
	HasSuicided(common.Address) bool

	// Exist reports whether the given account exists in state.
	// Notably this should also return true for suicided accounts.
	Exist(common.Address) bool
	// Empty returns whether the given account is empty. Empty
	// is defined according to EIP161 (balance = nonce = code = 0).
	Empty(common.Address) bool
	PrepareAccessList(rules params.Rules, sender, coinbase common.Address, dest *common.Address, precompiles []common.Address, txAccesses types.AccessList)
	AddressInAccessList(addr common.Address) bool
	SlotInAccessList(addr common.Address, slot common.Hash) (addressOk bool, slotOk bool)
	// AddAddressToAccessList adds the given address to the access list. This operation is safe to perform
	// even if the feature/fork is not active yet
	AddAddressToAccessList(addr common.Address)
	// AddSlotToAccessList adds the given (address,slot) to the access list. This operation is safe to perform
	// even if the feature/fork is not active yet
	AddSlotToAccessList(addr common.Address, slot common.Hash)

	RevertToSnapshot(int)
	Snapshot() int

	AddLog(*types.Log)
	AddPreimage(common.Hash, []byte)

	ForEachStorage(common.Address, func(common.Hash, common.Hash) bool) error

	IsIDDeactivated(id string, blockNumber *big.Int) bool

	GetLastDIDTxData(idKey []byte, config *params.ChainConfig) (*did.DIDTransactionData, error)

	GetAllDIDTxData(idKey []byte, config *params.ChainConfig) ([]did.DIDTransactionData, error)

	GetLastCustomizedDIDTxData(idKey []byte) (*did.DIDTransactionData, error)

	GetLastCustomizedDIDTxHash(idKey []byte) (elacom.Uint256, error)

	GetLastVerifiableCredentialTxData(idKey []byte, blockNumber *big.Int, config *params.ChainConfig) (*did.DIDTransactionData, error)

	GetCredentialExpiresHeight(credentIDKey []byte) (uint32, error)

	GetRevokeCredentialCtrls(credentIDKey []byte) ([]string, error)

	AddDIDLog(did string, operation string, doc []byte)

	IsDID(did string) (bool, error)

	ReadTransaction(txID common.Hash) (*types.Transaction, common.Hash, uint64, uint64)

	ReadBlock(hash common.Hash, number uint64) *types.Block

	GetDeactivatedTxData(idKey []byte, config *params.ChainConfig) (*did.DIDTransactionData, error)

	GetDIDExpiresHeight(idKey []byte) (uint32, error)
}

// CallContext provides a basic interface for the EVM calling conventions. The EVM
// depends on this context being implemented for doing subcalls and initialising new EVM contracts.
type CallContext interface {
	// Call another contract
	Call(env *EVM, me ContractRef, addr common.Address, data []byte, gas, value *big.Int) ([]byte, error)
	// Take another's contract code and execute within our own context
	CallCode(env *EVM, me ContractRef, addr common.Address, data []byte, gas, value *big.Int) ([]byte, error)
	// Same as CallCode except sender and value is propagated from parent to child scope
	DelegateCall(env *EVM, me ContractRef, addr common.Address, data []byte, gas *big.Int) ([]byte, error)
	// Create a new contract
	Create(env *EVM, me ContractRef, data []byte, gas, value *big.Int) ([]byte, common.Address, error)
}
