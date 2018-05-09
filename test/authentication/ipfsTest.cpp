#include <gtest/gtest.h>
#include "network/zkidIPFSGateway.h"

class ConfigIPFSTest : public ConfigIPFSInterface
{
  public:
    std::string GetIPFSClientIP(){
        return "localhost";
    };

    int GetIPFSClientPort(){
        return 4000;
    };
};

TEST(IPFSTest, TestMerklePathConstruction)
{
    std::vector<std::string> tree= {
        "64c68d1874aef5e808b7a8a9d9ef58237ba29b5aeb6e2dfb8ec9494701b8fc1d"
    };

    ConfigIPFSTest config;
    zkidIPFSGateway gateway(&config);
}