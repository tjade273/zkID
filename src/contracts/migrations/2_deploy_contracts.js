const Pairing = artifacts.require("Pairing");
const Verifier = artifacts.require("Verifier");
const LotteryContract = artifacts.require("LotteryContract");
const ExampleIssuer = artifacts.require("ExampleIssuer");

module.exports = function(deployer){
    deployer.deploy(Pairing);
    deployer.link(Pairing, Verifier);
    deployer.deploy(Verifier);
    deployer.deploy(ExampleIssuer);
    deployer.link(Verifier, LotteryContract);
    deployer.deploy(LotteryContract, 0);
}
