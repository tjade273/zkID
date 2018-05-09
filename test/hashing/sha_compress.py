#!/usr/bin/env python3
import random
import struct
import json
from os import urandom
import pypy_sha256 as sha256
from sys import argv

# Takes 64 bytes and returns 32
def sha_compress(data):
    assert(len(data) == 64)
    state = sha256.sha_init()
    state["data"] = data
    sha256.sha_transform(state)
    return struct.pack(">"+"I"*8, *state["digest"])

if __name__ == "__main__":
    leaf =  urandom(64)
    h = sha_compress(leaf)
    tree = {"root" : "", "leaf": leaf.hex(), "path" : []}
    for i in range(int(argv[1])):
        sibling = urandom(32)
        right = bool(urandom(1)[0]%2)
        #right = True
        h = sha_compress(h+sibling if right else sibling+h)
        tree["path"].append({"hash": sibling.hex(), "right": right})
    tree["root"] = h.hex()
    print(json.dumps(tree, indent=4, separators=(',', ': ')))
