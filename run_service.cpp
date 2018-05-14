#include <chrono>
#include <thread>
#include "cxxopts/cxxopts.hpp"
#include "network/ZkidService.h"
#include "configuration/ZkidConfiguration.h"
#include "network/zkidIPFSGateway.h"
#include "network/IPFSServiceController.h"

int main(int argc, char **argv)
{
    cxxopts::Options options("ZKID Service", "Zero-Knowledge identity proof generation service and credential manager for the Ethereum Blockcahin.");
    options.add_options()("f,configuration-file", "Path to file where service configuration file is stored", cxxopts::value<std::string>()->default_value(""));
    options.add_options()("l,ipfs-flag", "Launch local ipfs service", cxxopts::value<bool>()->default_value("false"));
    options.add_options()("u,upload-merke-tree","Uploads a merkle tree at given file",cxxopts::value<std::string>()->default_value(""));
    auto result = options.parse(argc, argv);

    IPFSServiceController ipfs_service;

    std::string config_file_path = result["f"].as<std::string>();

    if(config_file_path.empty()){
        ZkidService::console->error("Please supply a configuration file with the -f option");
        return 0;
    }

    ZkidConfiguration config(config_file_path);
    CredentialsManager cred_manager(&config);
    zkidIPFSGateway zkidIPFSGateway(&config);

    try
    {
        ZkidService service(&config, &cred_manager, &zkidIPFSGateway);

        service.console->info("Loading user credentials from: {0}", config.GetCredentialsFilePath());
        cred_manager.LoadCredentials();

        if (result["l"].as<bool>())
        {
            service.console->info("Starting IPFS daemon...", service.GetPort());
            ipfs_service.StartService();
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        std::string merkle_file_path = result["u"].as<std::string>();

        if(!merkle_file_path.empty()){
            Json::Value v = JsonObjectFromFile(merkle_file_path);

            std::vector<std::string> tree;
            for(int i = 0; i < v["merkle_proof"].size(); i++){
                tree.push_back(v["merkle_proof"][i].asString());
            }

            std::string merkle_tree_address = zkidIPFSGateway.PutMerkleTree(tree);
            service.console->info("Stored merkle tree from {0} at {1}", merkle_file_path,merkle_tree_address);
        }
        if (service.Start())
        {
            service.console->info("Started zkid service on port {0} successfully!", service.GetPort());
            getchar();
            service.Stop();
            ipfs_service.StopService();
        }
        else
        {
            service.console->info("Failed to start zkid service on port {0}", service.GetPort());
        }


    }
    catch (jsonrpc::JsonRpcException &e)
    {
        ZkidService::console->error(e.what());
    }
}
