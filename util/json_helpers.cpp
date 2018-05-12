#include "util/json_helpers.h"

Json::Value JsonObjectFromFile(const std::string &path)
{
    //read in test file;
    std::ifstream f(path);

    if (!f)
        std::cout << "Failed to open file stream" << std::endl;

    Json::Value j;
    f >> j;
    return j;
}