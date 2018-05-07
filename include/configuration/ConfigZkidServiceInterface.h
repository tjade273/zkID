#ifndef _ConfigZkidService_h
#define _ConfigZkidService_h

#include <string>
#include "configuration/ConfigProverInterface.h"

class ConfigZkidServiceInterface : public ConfigProverInterface{
    virtual const std::string& GetServiceAddress() = 0;
};
#endif