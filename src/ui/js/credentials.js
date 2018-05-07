web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"));

abi = JSON.parse('[{"constant":false,"inputs":[{"name":"candidate","type":"bytes32"}],"name":"Join","outputs":[{"name":"","type":"uint8"}],"payable":false,"type":"function","credentials":[{"issuer_address":"0xdeadbeef","range_high":"0x0","range_low":"0x0","k_factor":"0x0","description":"Confirms holder is over 18."}]}]')


CredentialsContract = web3.eth.contract(abi);
// In your nodejs console, execute contractInstance.address to get the address at which the contract is deployed and change the line below to use your deployed address
contractInstance = CredentialsContract.at("CONTRACT_ADDR");
currentPrompt = null;

var CredentialAction = function (contract, functionName) {
    this.functionName = functionName;
    this.requiredCredentials = abi.filter(function (e) {
        return e["name"] === functionName;
    })[0]["credentials"];
}

var CredentialsPrompt = function (credentialAction) {
    this.action = credentialAction;
}

CredentialAction.prototype.FetchCredentialProofs = function () {
        $.get("http://localhost:4444", this.requiredCredentials, function (data) {
            if(data["success"]){
                DoVerification(data["proofs"]);
            }else{
                FailedToGenerateProofs();
            }
        }, "json").fail(function () {
            UnableToConnectToProverService();
        });
}

function UnableToConnectToProverService(){

}

OnApprove = function () {
    //query prover rpc for proofs and send to contract. Catch "verified event" and finish.
    var action = currentPrompt.action;
    var res = action.FetchCredentialProofs();
}

OnDeny = function () {
    $("#modal-container").remove();
}

CredentialsPrompt.prototype.display = function () {

    $("#main-container").after("<div id='modal-container'></div>");
    $("#modal-container").load("html/modal.html", function () {
        var table = document.getElementById("credential_table");
        var requiredCredentials = currentPrompt.action.requiredCredentials;

        for (var i = 0; i < requiredCredentials.length; i++) {
            var current_cred = requiredCredentials[i];
            var cred_row = document.createElement("tr");
            var cred_sig_cell = document.createElement("td");
            var cred_sig = document.createTextNode(current_cred["address"]);
            var cred_desc_cell = document.createElement("td");;
            var cred_desc = document.createTextNode(current_cred["description"]);

            cred_sig_cell.appendChild(cred_sig);
            cred_desc_cell.appendChild(cred_desc);
            cred_row.appendChild(cred_sig_cell)
            cred_row.appendChild(cred_desc_cell)
            table.appendChild(cred_row);
        }

        var modal = document.getElementById("credentials-modal");
        var action_name = document.getElementById("action-name");
        action_name.appendChild(document.createTextNode(currentPrompt.action.functionName));
        modal.style.display = "inherit";
    });
};

function DoCredentialsAction(functionName) {
    var action = new CredentialAction(CredentialsContract, functionName);
    var prompt = new CredentialsPrompt(action);
    prompt.display();
    currentPrompt = prompt;
}

