#ifndef _json_helpers_h
#define _json_helpers_h

#include <jsoncpp/json/json.h>
#include <fstream>
#include <iostream>

Json::Value JsonObjectFromFile(const std::string &path);

#endif