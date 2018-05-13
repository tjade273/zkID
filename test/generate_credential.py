#!/usr/bin/env python3
import struct
import json
from os import urandom
from sys import argv
from random import getrandbits, randint
from hashing.sha_compress import path, sha_compress

def pretty_print(j):
    print(json.dumps(j, indent=4, separators=(',', ': ')))

class Credential(object):
    def __init__(self, secret_key, attributes):
        self.secret_key = secret_key
        self.attributes = attributes

        self.attr_string = struct.pack(">"+"I"*7, *attributes)

    def generate_proof_params(self, contract_salt, upper_bounds, lower_bounds, k_bound, k, n):
        serial = sha_compress(self.secret_key+ b"\x00"+contract_salt + struct.pack(">I", k))
        return {"sk" : self.secret_key.hex(),
                 "attributes" : self.attr_string.hex(),
                 "upper_bounds": struct.pack(">"+"I"*7, *upper_bounds).hex(),
                 "lower_bounds": struct.pack(">"+"I"*7, *lower_bounds).hex(),
                 "k_bound": k_bound,
                 "k": k,
                 "contract_salt": contract_salt.hex(),
                 "serial_number": serial.hex(),
                 "merkle_proof" : path(n, self.secret_key+b"\x00"*4+self.attr_string)}

if __name__ == "__main__":
    sk = urandom(32)
    attrs = [getrandbits(32) for _ in range(7)]
    cred = Credential(sk, attrs)
    uppers = list(map(lambda x: randint(x, 2**32), attrs))
    lowers = list(map(lambda x: randint(0, x), attrs))
    k = randint(0, 2**32)
    k_bound = randint(k, 2**32)
    contract_salt = urandom(27)
    n = int(argv[1])
    proof = cred.generate_proof_params(contract_salt, uppers, lowers, k_bound, k, n)
    pretty_print(proof)
