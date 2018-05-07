#include "proving/zkidMTA.h"

void AuthenticationArgsFromJson(const std::string &path_to_json, std::string &leaf, std::string &root,
                                std::vector<MTAuthenticationNode> &path)
{
    Json::Value j = JsonObjectFromFile(path_to_json);
    root = j["root"].asString();
    leaf = j["leaf"].asString();
    Json::Value path_hashes = j["path"];
    int tree_depth = path_hashes.size();

    path.resize(tree_depth);

    //construct authentication path
    for (int cur_depth = tree_depth - 1; cur_depth >= 0; --cur_depth)
    {
        Json::Value current_node = path_hashes[cur_depth];
        const std::string node_hash = (current_node)["hash"].asString();
        const bool is_right = (current_node)["right"].asBool();
        path[cur_depth] = MTAuthenticationNode(node_hash, is_right);
    }
}