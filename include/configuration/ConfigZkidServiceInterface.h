#ifndef _ConfigZkidServiceInterface_h
#define _ConfigZkidServiceInterface_h

#include <string>
#include "configuration/ConfigRPCServerInterface.h"

class ConfigZkidServiceInterface : public ConfigRPCServerInterface
{
  public:
    virtual int GetServicePort() = 0;
};
#endif