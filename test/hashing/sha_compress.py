#!/usr/bin/env python3
import random
import struct
import json
from os import urandom
from . import pypy_sha256 as sha256
from sys import argv

# Takes 64 bytes and returns 32
def sha_compress(data):
    assert(len(data) == 64)
    state = sha256.sha_init()
    state["data"] = data
    sha256.sha_transform(state)
    return struct.pack(">"+"I"*8, *state["digest"])

def full_tree(depth):
    idx = (1 << (depth+1)) - 2
    tree = [0]*(idx+1)
    tree_json = [0]*(idx+1)
    idx_temp = idx
    for i in range(int(idx_temp/2) + 1):
        leaf = urandom(64)
        h = sha_compress(leaf)
        tree[idx] = h
        tree_json[idx]= (h.hex())
        idx -= 1

    level_nodes = (1 << (depth+1)) / 4
    while(idx >= 0):
        for i in range(int(level_nodes)):
            h = sha_compress(tree[2*idx + 1] + tree[2*idx + 2])
            tree[idx] = h
            tree_json[idx] = h.hex()
            idx-=1
        level_nodes/=2
        depth-=1

    return tree_json

def path(count, leaf=None):
    if leaf is None:
        leaf = urandom(64)
    h = sha_compress(leaf)
    tree = {"root": "", "leaf": leaf.hex(), "path": []}
    for i in range(count):
        sibling = urandom(32)
        right = bool(urandom(1)[0]%2)
        h = sha_compress(h+sibling if right else sibling+h)
        tree["path"].append({"hash": sibling.hex(), "right": right})
    tree["root"] = h.hex()
    return tree

if __name__ == "__main__":
    if len(argv) < 3:
            print("Specify valid generation type (p: path | t: full tree) and count.")
            exit()
    gen_type = argv[1]
    gen_count = argv[2]
    if gen_type == 'p':
        print(json.dumps(path(int(gen_count)), indent=4, separators=(',', ': ')))
    elif gen_type == 't':
        print(json.dumps(full_tree(int(gen_count)),indent=4,separators=(',', ': ')))
    else:
        print("Specify valid generation type (p: path | t: full tree)")
