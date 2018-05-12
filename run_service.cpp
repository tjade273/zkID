#include "cxxopts/cxxopts.hpp"
#include "network/ZkidService.h"
#include "configuration/ZkidConfiguration.h"
#include "network/zkidIPFSGateway.h"
#include "network/IPFSServiceController.h"

int main(int argc, char **argv)
{
    cxxopts::Options options("ZKID Service", "Zero-Knowledge identity proof generation service and credential manager for the Ethereum Blockcahin.");
    options.add_options()("f,configuration-file", "Path to file where service configuration file is stored", cxxopts::value<std::string>());
    options.add_options()("l,ipfs-flag", "Launch local ipfs service", cxxopts::value<bool>());
    auto result = options.parse(argc, argv);

    IPFSServiceController ipfs_service;

    ZkidConfiguration config(result["f"].as<std::string>());
    CredentialsManager cred_manager(&config);
    zkidIPFSGateway zkidIPFSGateway(&config);

    try
    {
        ZkidService service(&config, &cred_manager, &zkidIPFSGateway);
        if (result["l"].as<bool>())
        {
            service.console->info("Starting IPFS daemon...", service.GetPort());
            ipfs_service.StartService(argv);
        }
        if (service.Start())
        {
            service.console->info("Started zkid service on port {0} successfully!", service.GetPort());
            getchar();
            service.Stop();
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
