#include "cxxopts/cxxopts.hpp"
#include "network/ZkidService.h"
#include "configuration/ZkidConfiguration.h"

int main(int argc, char **argv)
{
    cxxopts::Options options("ZKID Service", "Zero-Knowledge identity proof generation service and credential manager for the Ethereum Blockcahin.");
    options.add_options()("f,configuration-file", "Path to file where service configuration file is stored", cxxopts::value<std::string>());

    auto result = options.parse(argc, argv);

    ZkidConfiguration config(result["f"].as<std::string>());
    CredentialsManager cred_manager(&config);

    try
    {
        ZkidService service(&config, &cred_manager);
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
