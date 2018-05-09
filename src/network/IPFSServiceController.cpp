#include "network/IPFSServiceController.h"

void IPFSServiceController::StartService(char** argv)
{
    pid_t pid = fork();
    if (pid == 0)
    {
        execv("/usr/local/bin/ipfs", argv);
        exit(127);
    }
    else
    {
        this->_ipfs_process_id = pid;
    }
}

void IPFSServiceController::StopService()
{
    kill(this->_ipfs_process_id, SIGTERM);
}