#ifndef _ConfigCredentialsInterface_h
#define _ConfigCredentialsInterface_h

class ConfigCredentialsInterface
{
  public:
    virtual std::string GetCredentialsFilePath() = 0;
};

#endif