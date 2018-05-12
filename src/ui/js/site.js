web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"));
lottery_abi = JSON.parse('[{"constant":false,"inputs":[],"name":"Join","outputs":[],"payable":false,"type":"function","credentials":[{"issuer_address":"0xdeadbeef","range_high":0,"range_low":0,"k_factor":0,"description":"Confirms holder is over 18."},{"issuer_address":"0xfeedbeef","range_high":0,"range_low":0,"k_factor":0,"description":"Confirms holder is American."}]}]')

LotteryContract = web3.eth.contract(lottery_abi);
contractInstance = LotteryContract.at("CONTRACT_ADDR");

function OnJoinClick() {
    var credBlock = new CredentialBlock("Join", PartialAppJoin(), lottery_abi);
    credBlock.display();
}

/* Use partial application to supply non-proof arguments */

function PartialAppJoin(/* Insert non-proof arguments here*/) {
    return function (proof_bytes) {
        contractInstance.methods["Join"](proof_bytes).send();
    }
}