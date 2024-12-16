from src.pyvrf_r255 import ECVRF
from pysodium import crypto_box_seed_keypair, randombytes, crypto_kdf_hkdf_sha256_expand


def generate_key_pair(sk: bytes, info=b"derive key pair") -> tuple[bytes, bytes, bytes, bytes]:
    alpha = randombytes(32)
    vrf = ECVRF(sk)
    pi, beta = vrf.hash(alpha)
    seed = crypto_kdf_hkdf_sha256_expand(32, beta, info)
    PK, SK = crypto_box_seed_keypair(seed)

    return PK, SK, alpha, pi


def verify_key_pair(SK: bytes, pk: bytes,  alpha: bytes, pi: bytes, info=b"derive key pair") -> bool:
    beta = ECVRF.verify(pk, alpha, pi)
    seed = crypto_kdf_hkdf_sha256_expand(32, beta, info)
    PK_1, SK_1 = crypto_box_seed_keypair(seed)
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
