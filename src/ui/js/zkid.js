
issuer_abi = JSON.parse('[ { "constant": false, "inputs": [], "name": "getMerkleRootAddress", "outputs": [], "payable": false, "type": "function"}]');
IssuerContract = web3.eth.contract(issuer_abi);
currentBlock = null;

function ProofToBytes(proof) {
    return [].concat(
        web3.utils.hexToBytes(proof["A"][0]),
        web3.utils.hexToBytes(proof["A"][1]),
        web3.utils.hexToBytes(proof["A_p"][0]),
        web3.utils.hexToBytes(proof["A_p"][1]),
        web3.utils.hexToBytes(proof["B"][0]),
        web3.utils.hexToBytes(proof["B"][1]),
        web3.utils.hexToBytes(proof["B"][2]),
        web3.utils.hexToBytes(proof["B"][3]),
        web3.utils.hexToBytes(proof["B_p"][0]),
        web3.utils.hexToBytes(proof["B_p"][1]),
        web3.utils.hexToBytes(proof["C"][0]),
        web3.utils.hexToBytes(proof["C"][1]),
        web3.utils.hexToBytes(proof["C_p"][0]),
        web3.utils.hexToBytes(proof["C_p"][1]),
        web3.utils.hexToBytes(proof["H"][0]),
        web3.utils.hexToBytes(proof["H"][1]),
        web3.utils.hexToBytes(proof["K"][0]),
        web3.utils.hexToBytes(proof["K"][1]));
}

CredentialBlock.prototype.FetchCredentialProofs = function () {
    var client = new zkidclient("http://localhost:8383");

    this.action.requiredCredentials = this.action.requiredCredentials.map((e) => {
        //ask each verifier contract for the address of its merkle root
        try {
            var issuerContractInstance = IssuerContract.at(e["contract_salt"]);
            e["merkle_root_address"] = issuerContractInstance.getMerkleRootAddress().call();
        } catch (e) {
            e["merkle_root_address"] = "";
        } finally {
            return e;
        }
    });

    client.GenerateProofs(this.action.requiredCredentials, (id, result) => {
        var generated_proofs = result["proofs"];
        this.highlightCredentials(generated_proofs);

        if (result["success"]) {
            var proof_bytes = generated_proofs.reduce(function (acc, e) {
                acc.concat(ProofToBytes(e));
            }, []);
            action.method(proof_bytes,generated_proofs.length);
        } else {
            $("#msg-container").first().text("A proof could not be generated for one or more credentials.");
            $("#msg-container").show();
            $("#return-button-container").show();
        }
    }, function (code, msg) {
        PostFetchError(code, msg);
    });
}

CredentialBlock.prototype.highlightCredentials = function (generated_proofs) {
    $("#credential_table").find("tr:not(:first-child)").each(function () {
        var issuer_addr = $(this).find(">:first-child").text();
        var was_generated = generated_proofs == null ? false : generated_proofs.reduce(function (acc, e) {
            return acc ? true : e["issuer_address"] === issuer_addr;
        }, false);
        if (was_generated)
            $(this).animate({ backgroundColor: "#C8E6C9" }, 500);
        else
            $(this).animate({ backgroundColor: "#EF9A9A" }, 500);
    });
}

CredentialBlock.prototype.display = function () {
    $("#main-container").after("<div id='modal-container'></div>");
    $("#modal-container").load("html/modal.html", () => {
        var table = document.getElementById("credential_table");
        var requiredCredentials = this.action.requiredCredentials;

        for (var i = 0; i < requiredCredentials.length; i++) {
            var current_cred = requiredCredentials[i];
            var cred_row = document.createElement("tr");
            var cred_sig_cell = document.createElement("td");
            var cred_sig = document.createTextNode(current_cred["contract_salt"]);
            var cred_desc_cell = document.createElement("td");;
            
            var cred_desc_table = document.createElement("table");
            

            console.log(current_cred);
            for(var i = 0; i < current_cred["requested_attributes"].length; i++){
                var current_attr = current_cred["requested_attributes"][i];
                var desc_row = document.createElement("tr");
                var cred_desc = document.createTextNode(current_attr["description"]);
                desc_row.appendChild(cred_desc);
                cred_desc_table.appendChild(desc_row);
            }

            cred_sig_cell.appendChild(cred_sig);
            cred_desc_cell.appendChild(cred_desc_table);
            cred_row.appendChild(cred_sig_cell)
            cred_row.appendChild(cred_desc_cell)
            table.appendChild(cred_row);
        }

        $("#action-name").text(this.action.methodName);
        $("#credentials-modal").show();
    });
};

//method should be a partial application of desired method with the non-proof arguments already applied
function CredentialBlock(methodName, method, abi) {
    this.action = new CredentialMethod(methodName, method, abi);
    currentBlock = this;
}

var CredentialMethod = function (methodName, method, abi) {
    this.methodName = methodName;
    this.method = method;
    this.requiredCredentials = abi.find(function (e) {
        return e["name"] === methodName;
    })["credentials"];
}

function PostVericiationError(code, msg) {
    //Display that the credentials could not be verified
}

function PostFetchError(code, msg) {
    console.log("Code:%i Msg:%s", code, msg);
}

OnApprove = function () {
    currentBlock.FetchCredentialProofs();
}

OnReturn = function () {
    $("#modal-container").remove();
}