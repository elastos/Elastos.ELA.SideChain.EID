"use strict";

const Web3 = require("web3");
const web3 = new Web3("http://127.0.0.1:20646");
const ctrt = require("./ctrt");
const pledgeBillContract = require("./pledgeBillContract");


web3.extend({
    methods: [{
        name: 'getFailedRechargeTxs',
        call: 'eth_getFailedRechargeTxs',
        params: 1,
    },
    {
            name: 'getFailedRechargeTxByHash',
            call: 'eth_getFailedRechargeTxByHash',
            params: 1,
    },
    {
        name: 'sendInvalidWithdrawTransaction',
        call: 'eth_sendInvalidWithdrawTransaction',
        params: 2,
    },
    {
        name: 'receivedSmallCrossTx',
        call: 'eth_receivedSmallCrossTx',
        params: 2,
    },
    {
        name: 'onSmallCrossTxSuccess',
        call: 'eth_onSmallCrossTxSuccess',
        params: 1,
    },
    {
        name: 'getFrozenAccounts',
        call: 'eth_getFrozenAccounts',
        params: 0,
    }
    ]
});
const contract = new web3.eth.Contract(ctrt.abi);
const pledgeBill = new web3.eth.Contract(pledgeBillContract.abi)
console.log(JSON.stringify(process.env.env));
switch (process.env.env) {
    case "rinkeby":
        console.log("0x762a042b8B9f9f0d3179e992d965c11785219599");
        contract.options.address = "0x762a042b8B9f9f0d3179e992d965c11785219599";
        pledgeBill.options.address = ""
        break;
    case "testnet":
        console.log("0x762a042b8B9f9f0d3179e992d965c11785219599");
        contract.options.address = "0x762a042b8B9f9f0d3179e992d965c11785219599";
        pledgeBill.options.address = ""
        break;
    case "mainnet":
        console.log("0x6F60FdED6303e73A83ef99c53963407f415e80b9");
        contract.options.address = "0x6F60FdED6303e73A83ef99c53963407f415e80b9";
        pledgeBill.options.address = ""
        break;
    default:
        console.log("config address");
        contract.options.address = ctrt.address;
        pledgeBill.options.address = pledgeBillContract.address
}
const payloadReceived = {name: null, inputs: null, signature: null};
const blackAdr = "0x0000000000000000000000000000000000000000";
const zeroHash64 = "0x0000000000000000000000000000000000000000000000000000000000000000";
const latest = "latest";

for (const event of ctrt.abi) {
    if (event.name === "PayloadReceived" && event.type === "event") {
        payloadReceived.name = event.name;
        payloadReceived.inputs = event.inputs;
        payloadReceived.signature = event.signature;
    }
}

const pledgeBillBurnEvent = pledgeBillContract.abi[0]

module.exports = {
    web3: web3,
    contract: contract,
    payloadReceived: payloadReceived,
    pledgeBillBurnEvent:pledgeBillBurnEvent,
    pledgeBillContract:pledgeBill,
    blackAdr: blackAdr,
    latest: latest,
    zeroHash64: zeroHash64,
    reterr: function(err, res) {
        console.log("Error Encountered: ");
        console.log(err.toString());
        console.log("============================================================");
        res.json({"error": err.toString(), "id": null, "jsonrpc": "2.0", "result": null});
        return;
    },
    retnum: function toNonExponential(num) {
        let value = num.toString()
        let numList = value.split(".")
        let returnValue = value
        if (numList.length > 1) {
            let precisionStr = numList[1]
            if (precisionStr.length > 8) {
                let b = precisionStr.substr(precisionStr.lastIndexOf(".") + 1,8)
                returnValue = numList[0] + "." + b
            }
        }
        return returnValue
    }
};
