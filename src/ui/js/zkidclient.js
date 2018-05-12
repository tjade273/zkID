
function zkidclient(url) {
    this.url = url;
    var id = 1;
    
    function doJsonRpcRequest(method, params, methodCall, callback_success, callback_error) {
        var request = {};
        if (methodCall)
            request.id = id++;
        request.jsonrpc = "2.0";
        request.method = method;
        if (params !== null) {
            request.params = params;
        }
        JSON.stringify(request);
        
        $.ajax({
            type: "POST",
            url: url,
            data: JSON.stringify(request),
            beforeSend: function() {
               $("#approve-deny-button-container").hide();
               $("#proving-spinner").show();
            },
            complete: function() {
                $("#proving-spinner").hide();
            },
            success: function (response) {
                if (methodCall) {
                    if (response.hasOwnProperty("result") && response.hasOwnProperty("id")) {
                        callback_success(response.id, response.result);
                    } else if (response.hasOwnProperty("error")) {
                        if (callback_error != null)
                            callback_error(response.error.code,response.error.message);
                    } else {
                        if (callback_error != null)
                            callback_error(-32001, "Invalid Server response: " + response);
                    }
                }
            },
            error: function (j,ts,et) {
                if (methodCall)
                    callback_error(-32002, et);
            },
            dataType: "json"
        });
        return id-1;
    }
    this.doRPC = function(method, params, methodCall, callback_success, callback_error) {
        return doJsonRpcRequest(method, params, methodCall, callback_success, callback_error);
    }
}

zkidclient.prototype.GenerateProofs = function(credential_descriptions, callbackSuccess, callbackError) {
    var params = {credential_descriptions : credential_descriptions};
    return this.doRPC("GenerateProofs", params, true, callbackSuccess, callbackError);
};
