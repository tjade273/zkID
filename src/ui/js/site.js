web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"));
lottery_abi = JSON.parse('[ { "constant": false, "inputs": [ { "indexed": false, "name": "proofs", "type": "uint[]" } ], "name": "Join", "outputs": [], "payable": false, "type": "function", "credentials": [ { "contract_salt": "0xdeadbeef", "k_bound": 1, "requested_attributes": [ { "idx": 0, "upper_bound": "0x7fffff", "lower_bound": "0x12", "description": "Confirms holder is over 18." }, { "idx": 1, "upper_bound": "0x01", "lower_bound": "0x01", "description": "Confirms holder is American." } ] } ] } ]');

LotteryContract = web3.eth.contract(lottery_abi);
contractInstance = LotteryContract.at("CONTRACT_ADDR");

function OnJoinClick() {
    var credBlock = new CredentialBlock("Join", PartialAppJoin(), lottery_abi);
    credBlock.display();
}

/* Use partial application to supply non-proof arguments */

function PartialAppJoin(/* Insert non-proof arguments here*/) {
    return function (proof_bytes, numOfProofs) {
        contractInstance.methods["Join"](proof_bytes,numOfProofs).send();
    }
}