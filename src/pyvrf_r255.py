from pysodium import crypto_scalarmult_ristretto255_base, crypto_scalarmult_ristretto255,\
    crypto_core_ristretto255_from_hash, crypto_core_ristretto255_scalar_reduce, crypto_core_ristretto255_scalar_mul, \
    crypto_core_ristretto255_scalar_add, crypto_core_ristretto255_is_valid_point, crypto_core_ristretto255_sub,\
    crypto_core_ristretto255_scalar_random
from hashlib import sha512


suite_string = b'\xFF' + b'c2sp.org/vrf-r255'
cLen = 16
ptLen = 32
q = pow(2, 252) + 27742317777372353535851937790883648493
identity = '0000000000000000000000000000000000000000000000000000000000000000'


class ECVRF:
    def __init__(self, x: bytes):
        if isinstance(x, bytes) and len(x) == 32:
            self.x = x
            self.Y = crypto_scalarmult_ristretto255_base(x)
        else:
            raise Exception("Invalid key")

    @classmethod
    def random_key(cls):
        x = crypto_core_ristretto255_scalar_random()
        return cls(x)

    @property
    def public_key(self):
        return self.Y

    @property
    def secret_key(self):
        return self.x

    def prove(self, alpha: bytes) -> bytes:
        encode_to_curve_salt = self.Y
        H = ECVRF_encode_to_curve(encode_to_curve_salt, alpha)
        Gamma = crypto_scalarmult_ristretto255(self.x, H)

        k = ECVRF_nonce_generation(self.x, H)
        U = crypto_scalarmult_ristretto255_base(k)
        V = crypto_scalarmult_ristretto255(k, H)

        c = ECVRF_challenge_generation(self.Y, H, Gamma, U, V)

        s = crypto_core_ristretto255_scalar_add(crypto_core_ristretto255_scalar_mul(c + (16 * b'\x00'), self.x), k)

        pi = Gamma + c + s

        return pi

    @staticmethod
    def proof_to_hash(pi: bytes) -> bytes:
        Gamma, c, s = ECVRF_decode_proof(pi)
        proof_to_hash_domain_separator_front = b'\x03'
        proof_to_hash_domain_separator_back = b'\x00'
        beta = sha512(suite_string + proof_to_hash_domain_separator_front + Gamma +
                      proof_to_hash_domain_separator_back).digest()

        return beta

    def hash(self, alpha: bytes) -> tuple[bytes, bytes]:
        pi = self.prove(alpha)
        beta = self.proof_to_hash(pi)

        return pi, beta

    @staticmethod
    def verify(PK_string: bytes, alpha_string: bytes, pi_string: bytes, validate_key=True) -> bytes:
        if crypto_core_ristretto255_is_valid_point(PK_string):
            Y = PK_string
        else:
            raise Exception("Invalid point")

        if validate_key and Y == bytes.fromhex(identity):
            raise Exception("Invalid point")

        encode_to_curve_salt = PK_string
        Gamma, c, s = ECVRF_decode_proof(pi_string)

        H = ECVRF_encode_to_curve(encode_to_curve_salt, alpha_string)
        U = crypto_core_ristretto255_sub(crypto_scalarmult_ristretto255_base(s), crypto_scalarmult_ristretto255(c + (16 * b'\x00'), Y))
        V = crypto_core_ristretto255_sub(crypto_scalarmult_ristretto255(s, H),  crypto_scalarmult_ristretto255(c + (16 * b'\x00'), Gamma))
        c1 = ECVRF_challenge_generation(Y, H, Gamma, U, V)
        if c == c1:
            return ECVRF.proof_to_hash(pi_string)
        else:
            raise Exception("Verification failed")


def ECVRF_decode_proof(pi_string: bytes) -> tuple[bytes, bytes, bytes]:
    gamma_string = pi_string[0:ptLen]
    c_string = pi_string[ptLen:ptLen + cLen]
    s_string = pi_string[ptLen + cLen:]
    if crypto_core_ristretto255_is_valid_point(gamma_string):
        Gamma = gamma_string
    else:
        raise Exception("Invalid point")

    c = c_string
    if int.from_bytes(s_string, 'little') >= q:
        raise Exception("Invalid input")

    s = s_string
    return Gamma, c, s

# https://github.com/C2SP/C2SP/blob/main/vrf-r255.md
def ECVRF_encode_to_curve(encode_to_curve_salt: bytes, alpha_string: bytes) -> bytes:
    encode_to_curve_domain_separator = b'\x82'
    hash_string = sha512(suite_string + encode_to_curve_domain_separator + encode_to_curve_salt + alpha_string).digest()

    return crypto_core_ristretto255_from_hash(hash_string)


# https://github.com/C2SP/C2SP/blob/main/vrf-r255.md
def ECVRF_nonce_generation(SK: bytes, h_string: bytes) -> bytes:
    nonce_generation_domain_separator = b'\x81'
    k_string = sha512(suite_string + nonce_generation_domain_separator + SK + h_string).digest()

    return crypto_core_ristretto255_scalar_reduce(k_string)


def ECVRF_challenge_generation(P1: bytes, P2: bytes, P3: bytes, P4: bytes, P5: bytes) -> bytes:
    challenge_generation_domain_separator_front = b'\x02'
    challenge_generation_domain_separator_back = b'\x00'
    str = suite_string + challenge_generation_domain_separator_front + P1 + P2 + P3 + P4 + P5 + \
          challenge_generation_domain_separator_back

    c_string = sha512(str).digest()

    return c_string[0:cLen]
