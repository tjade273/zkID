#include <gtest/gtest.h>
#include "network/zkidIPFSGateway.h"
#include "network/IPFSServiceController.h"

class ConfigIPFSTest : public ConfigIPFSInterface
{
  public:
    std::string GetIPFSClientIP()
    {
        return "localhost";
    };

    int GetIPFSClientPort()
    {
        return 5001;
    };
};

TEST(IPFSTest, TestMerklePathConstruction)
{

    IPFSServiceController ipfs_controller;
    char *argv[] = {"/usr/local/bin/ipfs", "daemon", "--offline" , NULL};
    ipfs_controller.StartService(argv);
    
    sleep(1);
    std::vector<std::string> tree = {
        "0aedb36c0bcfc75072b7499242cf740190ac0433717559868a13b7ffbc9f0d99",
        "f4ebaceb65dbdf0dbda8b1d890e4e5374dd8df05a7b3e07db8560389c418b985",
        "b55787cbdb6065cb354dbd7087fbf412853769f4c8cff266bd57a3089ed31133",
        "06f546a9542e280d04b43c41e06c5dc86c7e933500829769842221ff2cb0a998",
        "8a14572d0b922d4c3def7d34d0e75b85af7f3565bfba393e7bf2bf183e39e7d2",
        "d2ce416e121758a1cac9a98f6789648e6dd9f722b77a2bee15839ed3f476ee41",
        "753f528c9070d52dfde4384033e7fbc22ecceb2fb6ed49122a8d0d3465f3556d"};

    ConfigIPFSTest config;
    zkidIPFSGateway gateway(&config);
    std::string hash = gateway.PutMerkleTree(tree);

    std::vector<std::string> returned_path;
    gateway.GetMerklePath(hash, 0, returned_path);

    std::vector<std::string> correct_returned_path = {
        "b55787cbdb6065cb354dbd7087fbf412853769f4c8cff266bd57a3089ed31133",
        "8a14572d0b922d4c3def7d34d0e75b85af7f3565bfba393e7bf2bf183e39e7d2"};

    bool equal = std::equal(correct_returned_path.begin(), correct_returned_path.end(), returned_path.begin());
    ASSERT_TRUE(equal);

    ipfs_controller.StopService();
}