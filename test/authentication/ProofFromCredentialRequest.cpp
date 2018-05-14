#include <gtest/gtest.h>
#include "network/ZkidRPCServer.h"
#include "network/ZkidService.h"
#include "network/zkidIPFSGateway.h"
#include "configuration/ZkidConfiguration.h"
#include "network/IPFSServiceController.h"

TEST(TestProofRPC, TestProofFromCredentialRequest)
{
    libff::alt_bn128_pp::init_public_params();
    ZkidConfiguration config("test/res/zkid_test_config.json");

    CredentialsManager cred_manager(&config);
    cred_manager.LoadCredentials();
    zkidIPFSGateway zkidIPFSGateway(&config);
    ZkidService service(&config, &cred_manager, &zkidIPFSGateway);

    IPFSServiceController ipfs_service;

    ipfs_service.StartService();

    jsonrpc::HttpServer http_server(0);

    CredentialRequest req;
    req.k_bound = 1791871409;
    req.merkle_root_address = "QmWgxfXhs2rovrqDKoNSprrWpZKZiF9edUTVd7U2q3BR1M";
    req.contract_salt = "9f616104a4d4cafda53f8ccf95c5136684628fe0970f34dff50db8";
    std::string upper_bound = "afa0136fea32ccd3f72f9ca603e4bf975e882f739b2d6dff63b70bb7";
    std::string lower_bound = "02e7380c0a29d5fc4ad06a20b6c75ebbc139ca98183976d24be332b5";

    for (int i = 0; i < 7; i++)
    {
        AttributeRequest at_req;
        at_req.idx = i;
        at_req.lower_bound = lower_bound.substr(i*8,8);
        at_req.upper_bound = upper_bound.substr(i*8,8);;
        req.attribute_requests.push_back(at_req);
    }

    CredentialProof p;
    ASSERT_TRUE(service.GetProofForCredential(req, p));

    ipfs_service.StopService();
}