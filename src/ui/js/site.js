web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"));

lottery_abi = [{
    "constant": false,
    "inputs": [{ "indexed": false, "name": "proofs", "type": "uint[]" }],
    "name": "Join", "outputs": [], "payable": false, "type": "function",
    "credentials": [{
        "contract_salt": "9f616104a4d4cafda53f8ccf95c5136684628fe0970f34dff50db8",
        "k_bound": 1791871409,
        "requested_attributes": [
            {
                "idx": 0, 
                "lower_bound": "02e7380c",
                "upper_bound": "afa0136f",
                "description": "Confirms holder is over 18."
            },
            {
                "idx": 1, 
                "lower_bound": "0a29d5fc",
                "upper_bound": "ea32ccd3",
                "description": "Confirms holder is American."
            },
            {
                "idx": 2, 
                "lower_bound": "4ad06a20",
                "upper_bound": "f72f9ca6"
            },
            {
                "idx": 3, 
                "lower_bound": "b6c75ebb",
                "upper_bound": "03e4bf97"
            },
            {
                "idx": 4, 
                "lower_bound": "c139ca98",
                "upper_bound": "5e882f73"
            },
            {
                "idx": 5, 
                "lower_bound": "183976d2",
                "upper_bound": "9b2d6dff"
            },
            {
                "idx": 6, 
                "lower_bound": "4be332b5",
                "upper_bound": "63b70bb7"
            }
        ]
    }
    ]
}
];

LotteryContract = web3.eth.contract(lottery_abi);
contractInstance = LotteryContract.at("CONTRACT_ADDR");

function OnJoinClick() {
    var credBlock = new CredentialBlock("Join", PartialAppJoin(), lottery_abi);
    credBlock.display();
}

/* Use partial application to supply non-proof arguments */
function PartialAppJoin(/* Insert non-proof arguments here*/) {
    return function (proof_bytes, serial, joined_cb, error_cb) {
        contractInstance.methods.Join(proof_bytes, serial).send({ "from": web3.eth.getCoinbase() }, cb)
            .on("reciept", function (reciept) {
                if (reciept.events["Joined"] != undefined) {
                    joined_cb();
                } else if (reciept.events["Err"] != undefined) {
                    error_cb();
                } else {
                    console.log("Failed to capture a verifier event!")
                }
            })
    }
}
