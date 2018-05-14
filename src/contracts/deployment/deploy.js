
Web3 = require ("web3")
fs = require('fs')

web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"));
fs.readFile('../verifier.sol', function (err, data) {
    web3.eth.compile.solidity(data).then(function (result) {
        var pairingLibrary = new web3.eth.Contract(result["Pairing"]["info"]["abiDefinition"]);
        pairingLibrary.deploy({
            "data": result["Pairing"]["code"]
        }).send({
            "from": web3.eth.getCoinbase(),
            "gas": 6000000
        }).then(function (paringInstance) {
            var verifierLinkedCode = result["Verifier"]["code"].replace("__Pairing______", paringInstance.options.address);
            var verifierLibrary = new web3.eth.Contract(result["Verifier"]["info"]["abiDefinitions"]);
            verifierLibrary.deploy({
                "data": verifierLinkedCode
            }).send({
                "from": web3.eth.getCoinbase(),
                "gas": 6000000
            }).then(function (verifierInstance) {
                DeployExampleContract(verifierInstance.options.address);
            });
        });
    });
});

function DeployExampleContract(verifier_contract_address) {
    fs.readFile('../ExampleContract.sol', function (err, data) {
        web3.eth.compile.solidity(data).then(function (result) {
            var linked_code = result["code"].replace("__Verifier______", verifier_contract_address);
            var lotteryContract = new web3.eth.Contract(result["ExampleContract"]["info"]["abiDefinition"]);
            loterryContract.deploy({
                "data": result["ExampleContract"]["code"]
            }).send({
                "from": web3.eth.getCoinbase(),
                "gas": 6000000
            }).then(function (exampleContractInstance) {
                console.log("ExampleContract: " + exampleContractInstance.options.address);
            });
        })
    });
}

fs.readFile('../ExampleIssuer.sol', function (err, data) {
    web3.eth.compile.solidity(data).then(function (result) {
        var issuerContract = new web3.eth.Contract(result["info"]["abiDefinition"]);
        loterryContract.deploy({
            "data": result["code"]
        }).send({
            "from": web3.eth.getCoinbase(),
            "gas": 6000000
        }).then(function (exampleIssuerInstance) {
            console.log("ExampleIssuer: " + exampleIssuerInstance.options.address);
        });
    })
});

