web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"));

abi = "INSERT ABI HERE";

CredentialsContract = web3.eth.contract(abi);
// In your nodejs console, execute contractInstance.address to get the address at which the contract is deployed and change the line below to use your deployed address
contractInstance = CredentialsContract.at("CONTRACT_ADDR");


function CredentialAction(contract, actionName){
    this.contract = contract;
    this.actionName = actionName;
    this.requiredCredentials = [];
}

CredentialAction.getRequiredCredentials = function(){
    this.contract.GetRequiredCredentialCount(this.actionName).call({},function(err,count){
        for(var i = 0; i < count; i++){
            this.contract.getRequiredCredential(this.actionName,i).call({},function(err,res){
                var credentialObj = {signature:res["signature"], description:res[i]["description"]};
                this.requiredCredentials.push(credentialObj);
            });
        }
    }
}

function OnApprove(){
    //query prover rpc for proofs and send to contract. Catch "verified event" and finish
}

function OnDeny(){
    //User does not want to provide credentials, give static sorry page
}

function DisplayCredentialsModal() {
        var table = document.getElementById("credential_table");

        for(var i = 0; i < credentialsArr.length; i++){
            var current_cred = credentialsArr[i];
            var cred_row = document.createElement("tr");
            var cred_sig_cell = document.createElement("td");
            var cred_sig= document.createTextNode(current_cred["signature"]);
            var cred_desc_cell = document.createElement("td");;
            var cred_desc = document.createTextNode(current_cred["description"]);

            cred_sig_cell.appendChild(cred_sig);
            cred_desc_cell.appendChild(cred_desc);
            cred_row.appendChild(cred_sig_cell)
            cred_row.appendChild(cred_desc_cell)
            table.appendChild(cred_row);
        }

        var modal = document.getElementById("credentials_modal");
        modal.style.display = "inherit";
    });
}
  