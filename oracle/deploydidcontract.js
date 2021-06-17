"use strict";

const Web3 = require("web3");
const web3 = new Web3("http://127.0.0.1:20646");

const acc = web3.eth.accounts.decrypt({"address":"53781e106a2e3378083bdcede1874e5c2a7225f8","crypto":{"cipher":"aes-128-ctr","ciphertext":"bc53c1fcd6e31a6392ddc1777157ae961e636c202ed60fb5dda77244c5c4b6ff","cipherparams":{"iv":"c5d1a7d86d0685aa4542d58c27ae7eb4"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"409429444dabb5664ba1314c93f0e1d7a1e994a307e7b43d3f6cc95850fbfa9f"},"mac":"4c37821c90d35118182c2d4a51356186482662bb945f0fcd33d3836749fe59c0"},"id":"39e7770e-4bc6-42f3-aa6a-c0ae7756b607","version":3}, "123");  

console.log("===>", acc.address);

const didcontract=new web3.eth.Contract([
	{
		"inputs": [],
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "data",
				"type": "string"
			}
		],
		"name": "publishDidTransaction",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	}
]);

const didProxy=new web3.eth.Contract([
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "imple",
				"type": "address"
			}
		],
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": true,
				"internalType": "address",
				"name": "previousOwner",
				"type": "address"
			},
			{
				"indexed": true,
				"internalType": "address",
				"name": "newOwner",
				"type": "address"
			}
		],
		"name": "OwnershipTransferred",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": true,
				"internalType": "address",
				"name": "implementation",
				"type": "address"
			}
		],
		"name": "Upgraded",
		"type": "event"
	},
	{
		"stateMutability": "payable",
		"type": "fallback"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "newImplementation",
				"type": "address"
			}
		],
		"name": "_upgradeTo",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "getTarget",
		"outputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "owner",
		"outputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "renounceOwnership",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "newOwner",
				"type": "address"
			}
		],
		"name": "transferOwnership",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"stateMutability": "payable",
		"type": "receive"
	}
]);


const didBytes="0x608060405234801561001057600080fd5b506107a4806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c806303c6d2401461003b5780639d7f0bbf14610057575b600080fd5b610055600480360381019061005091906105a0565b610087565b005b610071600480360381019061006c91906105a0565b610118565b60405161007e919061065a565b60405180910390f35b6000601690506000602090506000602090506100a16104f3565b6000805a90506000879050858151019250848484838a86fa506001846000600181106100c957fe5b60200201511461010e576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016101059061067c565b60405180910390fd5b5050505050505050565b60606000601790506000602090506000610c809050610135610515565b6000805a90508488510191508383838a8985fa50600060405180602001604052806000815250905060005b60268160ff1610156101c857600061018a868360ff166064811061018057fe5b60200201516101d8565b90506000868360ff166064811061019d57fe5b602002015114156101ae57506101c8565b6101b8838261039c565b9250508080600101915050610160565b5080975050505050505050919050565b60606000602067ffffffffffffffff811180156101f457600080fd5b506040519080825280601f01601f1916602001820160405280156102275781602001600182028036833780820191505090505b5090506000805b60208163ffffffff1610156102d65760008160080263ffffffff1660020a8660001c0260001b9050600060f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916146102c8578084848151811061029057fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a90535082806001019350505b50808060010191505061022e565b5060008167ffffffffffffffff811180156102f057600080fd5b506040519080825280601f01601f1916602001820160405280156103235781602001600182028036833780820191505090505b50905060005b828110156103905783818151811061033d57fe5b602001015160f81c60f81b82828151811061035457fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053508080600101915050610329565b50809350505050919050565b6060600083905060008390506000815183510167ffffffffffffffff811180156103c557600080fd5b506040519080825280601f01601f1916602001820160405280156103f85781602001600182028036833780820191505090505b50905060008190506000805b85518110156104725785818151811061041957fe5b602001015160f81c60f81b83838060010194508151811061043657fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053508080600101915050610404565b5060005b84518110156104e45784818151811061048b57fe5b602001015160f81c60f81b8383806001019450815181106104a857fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053508080600101915050610476565b50829550505050505092915050565b6040518060200160405280600190602082028036833780820191505090505090565b60405180610c800160405280606490602082028036833780820191505090505090565b600061054b610546846106cd565b61069c565b90508281526020810184848401111561056357600080fd5b61056e848285610719565b509392505050565b600082601f83011261058757600080fd5b8135610597848260208601610538565b91505092915050565b6000602082840312156105b257600080fd5b600082013567ffffffffffffffff8111156105cc57600080fd5b6105d884828501610576565b91505092915050565b60006105ec826106fd565b6105f68185610708565b9350610606818560208601610728565b61060f8161075d565b840191505092915050565b6000610627600883610708565b91507f6469646572726f720000000000000000000000000000000000000000000000006000830152602082019050919050565b6000602082019050818103600083015261067481846105e1565b905092915050565b600060208201905081810360008301526106958161061a565b9050919050565b6000604051905081810181811067ffffffffffffffff821117156106c3576106c261075b565b5b8060405250919050565b600067ffffffffffffffff8211156106e8576106e761075b565b5b601f19601f8301169050602081019050919050565b600081519050919050565b600082825260208201905092915050565b82818337600083830152505050565b60005b8381101561074657808201518184015260208101905061072b565b83811115610755576000848401525b50505050565bfe5b6000601f19601f830116905091905056fea2646970667358221220e7d07abdea018d083d732ecd9a30cf110fb639b060cabc823657425f0029e97464736f6c63430007060033"

const proxyBytes="608060405234801561001057600080fd5b50604051610a1a380380610a1a8339818101604052602081101561003357600080fd5b8101908080519060200190929190505050600061005461010760201b60201c565b9050806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508073ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a3506101018161010f60201b60201c565b506101ce565b600033905090565b610122816101bb60201b61066c1760201c565b610177576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260338152602001806109e76033913960400191505060405180910390fd5b80600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b600080823b905060008111915050919050565b61080a806101dd6000396000f3fe60806040526004361061004e5760003560e01c80633414074814610067578063715018a6146100b85780638da5cb5b146100cf578063f00e6a2a14610110578063f2fde38b146101515761005d565b3661005d5761005b6101a2565b005b6100656101a2565b005b34801561007357600080fd5b506100b66004803603602081101561008a57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506101bc565b005b3480156100c457600080fd5b506100cd6102ba565b005b3480156100db57600080fd5b506100e4610427565b604051808273ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34801561011c57600080fd5b50610125610450565b604051808273ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34801561015d57600080fd5b506101a06004803603602081101561017457600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919050505061047a565b005b6101aa61067f565b6101ba6101b5610681565b6106ab565b565b6101c46106d1565b73ffffffffffffffffffffffffffffffffffffffff166101e2610427565b73ffffffffffffffffffffffffffffffffffffffff161461026b576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260208152602001807f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657281525060200191505060405180910390fd5b610274816106d9565b8073ffffffffffffffffffffffffffffffffffffffff167fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b60405160405180910390a250565b6102c26106d1565b73ffffffffffffffffffffffffffffffffffffffff166102e0610427565b73ffffffffffffffffffffffffffffffffffffffff1614610369576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260208152602001807f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657281525060200191505060405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff1660008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a360008060006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550565b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b6000600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b6104826106d1565b73ffffffffffffffffffffffffffffffffffffffff166104a0610427565b73ffffffffffffffffffffffffffffffffffffffff1614610529576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260208152602001807f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657281525060200191505060405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614156105af576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602681526020018061077c6026913960400191505060405180910390fd5b8073ffffffffffffffffffffffffffffffffffffffff1660008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a3806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b600080823b905060008111915050919050565b565b6000600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b3660008037600080366000845af43d6000803e80600081146106cc573d6000f35b3d6000fd5b600033905090565b6106e28161066c565b610737576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260338152602001806107a26033913960400191505060405180910390fd5b80600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505056fe4f776e61626c653a206e6577206f776e657220697320746865207a65726f20616464726573735570677261646561626c65426561636f6e3a20696d706c656d656e746174696f6e206973206e6f74206120636f6e7472616374a264697066735822122012f6ee548509d24bdc2183486ec5eb13e76b010675a0b47ae0a06fe67d61e33764736f6c634300070600335570677261646561626c65426561636f6e3a20696d706c656d656e746174696f6e206973206e6f74206120636f6e7472616374"


const data = didcontract.deploy({data: didBytes}).encodeABI();
const tx = {data: data, gas: "2000000", gasPrice: "2000000000"};

let didAddress = "";

acc.signTransaction(tx).then((stx) => {
	console.log("sign over", stx.rawTransaction)
    web3.eth.sendSignedTransaction(stx.rawTransaction).on("transactionHash", console.log).then(function(receipt) {
    	didAddress = receipt.contractAddress;
    	console.log("receipt", receipt, "didAddress", didAddress);
    	if (receipt.status == true) {
			deployProxy();
    	}
    	
    }).catch(console.log);
}).catch(console.log);

function deployProxy() {
	let data = didProxy.deploy({data: proxyBytes, arguments: [didAddress]}).encodeABI();
	let tx = {data: data, gas: "2000000", gasPrice: "2000000000"};

	acc.signTransaction(tx).then((stx) => {
	console.log("sign over", stx.rawTransaction)
    web3.eth.sendSignedTransaction(stx.rawTransaction).on("transactionHash", console.log).then(function(receipt) {
    	console.log("receipt", receipt);
    }).catch(console.log);
}).catch(console.log);

}