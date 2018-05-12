#ifndef _IPFSSerivceController_h
#define _IPFSSerivceController_h

#include <unistd.h>
#include <signal.h>
#include <cstdlib>

class IPFSServiceController
{
  public:
    void StartService(char** argv);
    void StopService();

  private:
    pid_t _ipfs_process_id;
};
#endif