from src.pyvrf_r255 import ECVRF
from pysodium import crypto_box_seed_keypair, randombytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

"""
In this example, an X25519 keypair is generated with the VRF output. 
With prior knowledge of the public key and alpha, someone can use pi to prove that he generated the keypair.

This is true because the following assertion holds:

For alpha and beta there exists only one keypair (sk, pk) and one proof pi such that
    VRF_verify(pk, alpha, pi) = ("VALID", beta)

Proof:
Assume that there exists a second keypair (sk_2, pk_2) != (sk, pk) and a proof pi_2 such that 
    VRF_verify(pk_2, alpha, pi_2) = ("VALID", beta)
Let 
    pi_3, beta_3 = VRF_hash(sk_2, alpha)

Then beta != beta_3 since sk != sk_2 and due the randomness

Therefore 
    VRF_verify(pk_2, alpha, pi_2) = ("VALID", beta)
    VRF_verify(pk_2, alpha, pi_3) = ("VALID", beta_3)
    beta != beta_3
 
This is a contradiction to the full-uniqueness property, see https://www.rfc-editor.org/rfc/rfc9381.html#name-full-uniqueness
"""


def generate_key_pair(sk: bytes, info=b"derive key pair") -> tuple[bytes, bytes, bytes, bytes]:
    alpha = randombytes(32)
    vrf = ECVRF(sk)
    pi, beta = vrf.hash(alpha)
    hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=info)
    seed = hkdf.derive(beta)
    PK, SK = crypto_box_seed_keypair(seed)

    return PK, SK, alpha, pi


def verify_key_pair(SK: bytes, pk: bytes,  alpha: bytes, pi: bytes, info=b"derive key pair") -> bool:
    hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=info)
    beta = ECVRF.verify(pk, alpha, pi)
    PK_1, SK_1 = crypto_box_seed_keypair(hkdf.derive(beta))
    if SK_1 == SK:
        return True
    else:
        raise Exception("Verification failed")



vrf = ECVRF.random_key()

# Get the secret Key
sk = vrf.secret_key

# Get the public Key
pk = vrf.public_key

PK, SK, alpha, pi = generate_key_pair(sk)
print(verify_key_pair(SK, pk, alpha, pi))