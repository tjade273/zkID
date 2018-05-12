#ifndef _ConfigZkidServiceInterface_h
#define _ConfigZkidServiceInterface_h

#include <string>
#include "configuration/ConfigProverInterface.h"
#include "configuration/ConfigRPCServerInterface.h"

class ConfigZkidServiceInterface : public ConfigProverInterface, public ConfigRPCServerInterface
{
  public:
    virtual int GetServicePort() = 0;
};
#endif