web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"));

lottery_abi = [{
    "constant": false,
    "inputs": [{ "indexed": false, "name": "proofs", "type": "uint[]" }],
    "name": "Join", "outputs": [], "payable": false, "type": "function",
    "credentials": [{
        "contract_salt": "0xdeadbeef",
        "k_bound": 1,
        "requested_attributes": [
            {
                "idx": 0, "upper_bound": "0x7fffff",
                "lower_bound": "0x12",
                "description": "Confirms holder is over 18."
            },
            {
                "idx": 1, "upper_bound": "0x01",
                "lower_bound": "0x01",
                "description": "Confirms holder is American."
            }]
    }]
}];

LotteryContract = web3.eth.contract(lottery_abi);
contractInstance = LotteryContract.at("CONTRACT_ADDR");

function OnJoinClick() {
    var credBlock = new CredentialBlock("Join", PartialAppJoin(), lottery_abi);
    credBlock.display();
}

/* Use partial application to supply non-proof arguments */
function PartialAppJoin(/* Insert non-proof arguments here*/) {
    return function (proof_bytes, serial, joined_cb,error_cb) {
        contractInstance.methods.Join(proof_bytes, serial).send({"from":web3.eth.getCoinbase()},cb)
        .on("reciept",function(reciept){
            if(reciept.events["Joined"] != undefined){
                joined_cb();
            }else if (reciept.events["Err"] != undefined){
                error_cb();
            }else{
                console.log("Failed to capture a verifier event!")
            }
        })    
    }
}
