#include "authentication/zkMTA.h"

using json = nlohmann::json;

void AuthenticationArgsFromJson(const std::string &path_to_json, std::string &leaf, std::string &root,
                                std::vector<MTAuthenticationNode> &path)
{
    //read in test file;
    std::ifstream f(path_to_json);

    if (!f)
        std::cout << "Failed to open file stream" << std::endl;

    json j;
    f >> j;

    root = j["root"];
    leaf = j["leaf"];
    json path_hashes = j["path"];
    int tree_depth = path_hashes.size();

    path.resize(tree_depth);

    //construct authentication path
    json::iterator cur_node_it = path_hashes.begin();
    for (int cur_depth = tree_depth - 1; cur_depth >= 0; ++cur_node_it, --cur_depth)
    {
        const std::string node_hash = (*cur_node_it)["hash"];
        const bool is_right = (*cur_node_it)["right"];
        path[cur_depth] = MTAuthenticationNode(node_hash, is_right);
    }
}