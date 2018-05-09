#include "network/zkidIPFSGateway.h"

zkidIPFSGateway::zkidIPFSGateway(ConfigIPFSInterface *ipfs_config) : _ipfs_config(ipfs_config), _client(ipfs_config->GetIPFSClientIP(), ipfs_config->GetIPFSClientPort())
{
}

void zkidIPFSGateway::GetMerklePath(const std::string &merkle_address, size_t address, std::vector<std::string> &path)
{
    /* The LSb of the address corresponds to the top-most level of the MT 
     * and the first element of path corresponds to the level right below 
     * the root.
     */

    ipfs::Json j;
    _client.ObjectGet(merkle_address, &j);

    ipfs::Json links = j["Links"];

    if (links.size() == 0)
        return; //hit leaf

    ipfs::Json left_addr = links[0]["Hash"];
    ipfs::Json right_addr = links[1]["Hash"];

    ipfs::Json path_element, next_parent;

    if (address & (1 << path.size()))
    {
        path_element = right_addr;
        next_parent = left_addr;
    }
    else
    {
        path_element = left_addr;
        next_parent = right_addr;
    }

    _client.ObjectGet(merkle_address, &path_element);
    path.push_back(path_element["Data"]);
    GetMerklePath(next_parent, address, path);
}

std::string zkidIPFSGateway::PutMerkleTree(const std::vector<std::string> &tree, int i)
{
    ipfs::Json node;
    node["Data"] = tree[i];

    if (i < tree.size() /  2)
    {
        // If the node is not a leaf add its children
        ipfs::Json left_link;
        left_link["Name"] = "Left Child";
        left_link["Hash"] = PutMerkleTree(tree, 2 * i);

        ipfs::Json right_link;
        right_link["Name"] = "Right Child";
        right_link["Hash"] = PutMerkleTree(tree, 2 * i + 1);

        node["Links"][0] = left_link;
        node["links"][1] = right_link;
    }

    ipfs::Json stored;
    _client.ObjectPut(node, &stored);
    return stored["Hash"];
}