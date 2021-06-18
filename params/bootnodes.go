// Copyright 2015 The Elastos.ELA.SideChain.EID Authors
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

package params

// MainnetBootnodes are the enode URLs of the P2P bootstrap nodes running on
// the main Ethereum network.
var MainnetBootnodes = []string{
	"enode://02acd3f3812d55d0e667427bf83dd1d5169800323c56e431750bbf55667cf45ef0cacd6a7c895a73170fe388524a7010a8063034a2212aefbe6cf2c7ef7c8b66@52.74.28.202:20640",
	"enode://d82fae81d36b61afa01339c402992dc44434a9ad427ac0c7ea170fe650c86de49dde11c9ed57a4f7661534ccd130e6b420bb2f7db2bacbbce15ecec6427ed6e7@52.62.113.83:20640",
	"enode://8839fc9b0cec7e63f0b3ffd0f6f6030ef05a0ccf2b47affdc59e8db5ac4b0ea2cbe52ac67b7e7a88060c38c1aa47f4eae2c12169b9f4c8d887bf6d3770aea206@35.156.51.127:20640",
	"enode://8104ddf1c74b602229df91cf72361b4579b94d024521860c3ffa0e693f2c98f93c084bc1c7fb9e548d486e925a589beadd7dedbd39fd4372ef14993e3a1b0d6c@35.177.89.244:20640",
	"enode://30b9671f88f7c6e018bc6801144306eddb8e685d0eba9833e6c8e9ee66135cb6fa1573b49ba11045468daef24cbadc861322060cd568286ebfa5060f928106ee@52.53.134.102:20640",
}

// TestnetBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// Ropsten test network.
var TestnetBootnodes = []string{
	"enode://5e1d6f9f74e33b2d1e2fda87efaf60a788b338c08eefd3a435e9c7de98645bc041421c27d9ed3927c7b5195febd691aff30de881842749f3030089df0e135232@3.208.184.54:20640",
	"enode://30dc2b7986e2ec5902498ec26fad6fcecece617aa1652f227f684ede6a0939bb7a205ada1c91420d30b427c86bbdcc31fdfd6d955dd8f5854370f583025a0708@3.209.35.13:20640",
	"enode://b0357d45e9070c1660f63f077e0e3b0054a18d93785589d498586b6e0b7ec7c5b39ef608e82e7280ca95019db7c36455275d98a3e8684916ba8f3a7aab4ad38b@3.210.227.193:20640",
}

// RinkebyBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// Rinkeby test network.
var RinkebyBootnodes = []string{
	"enode://fe44bc423f210805daad60cc5d308f449e9282c28a9aba91040d7c727cf5751d1ae9e85d32a430f4a6fe15c8eb52833a1747e8b28e6ed5ae291fdae32e6b9181@3.209.120.83:20640",
	"enode://777e2a86687d675c05344acc6e24cefbd3e233759e8b89d7b3d101aeffc89e6292f66a115c5bfc30f250c120e6a2354a7a6ea304439cfded706de1c9ade61abf@3.212.134.14:20640",
	"enode://deb84117dada6c2c8f9c5d9d44f749b6fbbefdc987a1611b683ead6e4e2ce8e0d05a196591a713376eee5d9c165d3888d2e175e8eb842e5a381f273c0268edca@3.212.156.65:20640",
}

// GoerliBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// Görli test network.
var GoerliBootnodes = []string{
	//"enode://fe44bc423f210805daad60cc5d308f449e9282c28a9aba91040d7c727cf5751d1ae9e85d32a430f4a6fe15c8eb52833a1747e8b28e6ed5ae291fdae32e6b9181@18.217.15.245:20640",
	//"enode://777e2a86687d675c05344acc6e24cefbd3e233759e8b89d7b3d101aeffc89e6292f66a115c5bfc30f250c120e6a2354a7a6ea304439cfded706de1c9ade61abf@18.217.15.245:20640",
	//"enode://deb84117dada6c2c8f9c5d9d44f749b6fbbefdc987a1611b683ead6e4e2ce8e0d05a196591a713376eee5d9c165d3888d2e175e8eb842e5a381f273c0268edca@18.217.15.245:20640",
	"enode://bcad5f7115806ded945d1d2dfb62fa1eb360466a962f8637348dd9e2a60c6b3d8d514b238a758c33502ba5a7487050880e0a575d36523b28189ab85f56a488df@34.229.27.111:20640",
	"enode://a03dd4e76943b43d94c48ff020c48b7423d75fd3ef3bf50625f0168110d71865803d7e0888c130f63589270f30ee3833efd05db2c5564f890d0cb5b28928fde7@3.129.117.39:20648",
}

// DiscoveryV5Bootnodes are the enode URLs of the P2P bootstrap nodes for the
// experimental RLPx v5 topic-discovery network.
var DiscoveryV5Bootnodes = []string{
	"enode://da476658b470ccfd35e7886cd8c971ef77fa0ae6557e963686af7ef3f09cf484ee3063301db2e33969b31dbbff480373911fa2e478cc583deb80ffa005c513c0@54.223.196.249:20000",
}
