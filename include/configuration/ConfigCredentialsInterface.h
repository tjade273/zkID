#ifndef _ConfigCredentialsInterface_h
#define _ConfigCredentialsInterface_h

class ConfigCredentialsInterface
{
  public:
    virtual const std::string &GetCredentialsFilePath() = 0;
};

#endif