#include "proving/zkidProverImpl.h"

void ProofRequestFromJson(const std::string &path, ProofRequest &proof){
  Json::Value j = JsonObjectFromFile(path);
  proof.secret_key = j["sk"].asString();
  proof.merkle_root = j["merkle_proof"]["root"].asString();
  Json::Value path_hashes = j["merkle_proof"]["path"];
  int tree_depth = path_hashes.size();
  proof.path.resize(tree_depth);

  for (int cur_depth = tree_depth - 1; cur_depth >= 0; --cur_depth)
    {
      Json::Value current_node = path_hashes[cur_depth];
      const std::string node_hash = (current_node)["hash"].asString();
      const bool is_right = (current_node)["right"].asBool();
      proof.path[cur_depth] = node_hash;
      proof.address |= (is_right << (tree_depth -1 - cur_depth));
    }

  proof.attributes = j["attributes"].asString();
  proof.upper_bounds = j["upper_bounds"].asString();
  proof.lower_bounds = j["lower_bounds"].asString();
  proof.k_bound = j["k_bound"].asUInt();
  proof.k = j["k"].asUInt();
  proof.salt = j["contract_salt"].asString();
}
