web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"));

abi = JSON.parse('[{"constant":false,"inputs":[{"name":"candidate","type":"bytes32"}],"name":"Join","outputs":[{"name":"","type":"uint8"}],"payable":false,"type":"function","credentials":[{"issuer_address":"0xdeadbeef","range_high":"0x0","range_low":"0x0","k_factor":"0x0","description":"Confirms holder is over 18."},{"issuer_address":"0xfeedbeef","range_high":"0x0","range_low":"0x0","k_factor":"0x0","description":"Confirms holder is American."}]}]')


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
        var action = currentPrompt.action;
        var client = new zkidclient("http://localhost:8383");
        client.GenerateProofs(action.requiredCredentials,function(id,result){
            generated_proofs = [{"issuer_address":"0xdeadbeef"}]; //TODO: replace with proofs from result
            HighlightCredentials(generated_proofs);
            if(result["success"]){
                //Take the credential proofs and send them to the contract function
            }else{
                $("#msg-container").first().text("A proof could not be generated for one or more credentials.");
                $("#msg-container").show();
                $("#return-button-container").show();
            }
        }, function(code,msg){
            PostFetchError(code,msg);
        });
}

function HighlightCredentials(generated_proofs){
    $("#credential_table").find("tr:not(:first-child)").each(function(){
        var issuer_addr = $(this).find(">:first-child").text();
        var was_verified = generated_proofs.reduce(function(acc,e){
            return acc ? true : e["issuer_address"] === issuer_addr; 
        },false);

        if(was_verified)
            $(this).animate({backgroundColor:"#C8E6C9"},500);
        else 
            $(this).animate({backgroundColor:"#EF9A9A"},500);
    });
}

function PostVericiationError(code, msg){
    //Display that the credentials could not be verified
}

function PostFetchError(code,msg){
    console.log("Code:%i Msg:%s",code,msg);
}

OnApprove = function () {
    //query prover rpc for proofs and send to contract. Catch "verified event" and finish.
    var action = currentPrompt.action;
    var res = action.FetchCredentialProofs();
}

OnReturn = function () {
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
            var cred_sig = document.createTextNode(current_cred["issuer_address"]);
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

function OnJoinClick(){
    CredentialBlock("Join",abi);
}


function CredentialBlock(functionName,abi) {
    var action = new CredentialAction(CredentialsContract, functionName);
    var prompt = new CredentialsPrompt(action);
    prompt.display();
    currentPrompt = prompt;
}