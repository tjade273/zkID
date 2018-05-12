#include "network/IPFSServiceController.h"

void IPFSServiceController::StartService(char** argv)
{
    if(!argv){
        argv =  new char*[3]{"/usr/local/bin/ipfs", "daemon", NULL};
    }

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

    free(argv);
}

void IPFSServiceController::StopService()
{
    kill(this->_ipfs_process_id, SIGTERM);
}