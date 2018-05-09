#ifndef _ConfigIPFSInterface_h
#define _ConfigIPFSInterface_h

class ConfigIPFSInterface{
    public:
        virtual std::string GetIPFSClientIP() = 0;
        virtual int GetIPFSClientPort() = 0;
};
#endif