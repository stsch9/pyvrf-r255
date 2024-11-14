# https://github.com/C2SP/C2SP/blob/main/vrf-r255.md#test-vector

import unittest
from src.pyvrf_r255 import ECVRF, ECVRF_encode_to_curve, suite_string
from hashlib import sha512


SK = '3431c2b03533e280b23232e280b34e2c3132c2b03238e280b23131e280b34500'
PK = '54136cd90d99fbd1d4e855d9556efea87ba0337f2a6ce22028d0f5726fcb854e'
alpha = '633273702e6f72672f7672662d72323535'
hash_string = '3907ed3453d308b0cb4ae071be7e5a80f7db05f11f5569016e3fa3996f7307821142133d0124fb3774d55ba6ccd14c11f71bf66038ec80b3f9973a1a6d69f5db'
H = 'f245308737c2a888ba56448c8cdbce9d063b57b147e063ce36c580194ef31a63'

# ???

pi = '0a97d961262fb549b4175c5117860f42ae44a123f93c476c439eddd1c0cff9265c805525233e2284dbed45e593b8eea31d5ca9734d72bcbba9738d5237f955f3b2422351149d1312503b6441a47c940c'
beta = 'dd653f0879b48c3ef69e13551239bec4cbcc1c18fe8894de2e9e1c790e18273603bf1c6c25d7a797aeff3c43fd32b974d3fcbd4bcce916007097922a3ea3a794'


class TestVRFr255(unittest.TestCase):
    def test_prove(self):
        vrf = ECVRF(bytes.fromhex(SK))
        self.assertEqual(vrf.public_key, bytes.fromhex(PK))

        pi_star = vrf.prove(bytes.fromhex(alpha))
        self.assertEqual(pi_star, bytes.fromhex(pi))

        beta_star = vrf.proof_to_hash(pi_star)
        self.assertEqual(beta_star, bytes.fromhex(beta))

    def test_prove2(self):
        vrf = ECVRF(bytes.fromhex(SK))
        pi_star, beta_star = vrf.hash(bytes.fromhex(alpha))
        self.assertEqual(pi_star, bytes.fromhex(pi))
        self.assertEqual(beta_star, bytes.fromhex(beta))

    def test_verify(self):
        beta_star = ECVRF.verify(bytes.fromhex(PK), bytes.fromhex(alpha), bytes.fromhex(pi))
        self.assertEqual(beta_star, bytes.fromhex(beta))

    def test_hash_string(self):
        encode_to_curve_domain_separator = b'\x82'
        hash_string_star = sha512(suite_string + encode_to_curve_domain_separator + bytes.fromhex(PK) + bytes.fromhex(alpha)).digest()
        self.assertEqual(hash_string_star, bytes.fromhex(hash_string))

    def test_H(self):
        h = ECVRF_encode_to_curve(bytes.fromhex(PK), bytes.fromhex(alpha))
        self.assertEqual(h, bytes.fromhex(H))

if __name__ == '__main__':
    unittest.main()