from pysodium import crypto_scalarmult_ristretto255_base, crypto_scalarmult_ristretto255,\
    crypto_core_ristretto255_from_hash, crypto_core_ristretto255_scalar_reduce, crypto_core_ristretto255_scalar_mul, \
    crypto_core_ristretto255_scalar_add, crypto_core_ristretto255_is_valid_point, crypto_core_ristretto255_sub
from hashlib import sha512
from src.pyvrf_r255 import ECVRF

SK = '3431c2b03533e280b23232e280b34e2c3132c2b03238e280b23131e280b34500'
alpha = '633273702e6f72672f7672662d72323535'
PK = crypto_scalarmult_ristretto255_base(bytes.fromhex(SK))

suite_string = b'\xFF' + b'c2sp.org/vrf-r255'
cLen = 16
ptLen = 32
q = pow(2,252) + 27742317777372353535851937790883648493
base = 'e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76'

def ECVRF_prove(SK: bytes, alpha_string: bytes):
    x = SK
    Y = crypto_scalarmult_ristretto255_base(x)
    print("Y: " + Y.hex())
    encode_to_curve_salt = Y

    H = ECVRF_encode_to_curve(encode_to_curve_salt, alpha_string)
    print("H: " + H.hex())
    h_string = H

    Gamma = crypto_scalarmult_ristretto255(x, H)
    print("Gamma: " + Gamma.hex())

    k = ECVRF_nonce_generation(SK, h_string)
    print("k: " + k.hex())

    U = crypto_scalarmult_ristretto255_base(k)
    print("U: " + U.hex())

    V = crypto_scalarmult_ristretto255(k, H)
    print("V: " + V.hex())

    c = ECVRF_challenge_generation(Y, H, Gamma, U, V)
    print("c: " + c.hex())

    s = crypto_core_ristretto255_scalar_add(crypto_core_ristretto255_scalar_mul(c + (16 * b'\x00'), x), k)
    print("s: " + s.hex())
    #print(crypto_core_ristretto255_scalar_reduce((int.from_bytes(k, 'little') + int.from_bytes(c, 'little') * int.from_bytes(x, 'little')).to_bytes(64, 'little')).hex())

    pi_string = Gamma + c + s

    return pi_string


def ECVRF_proof_to_hash(pi_string: bytes) -> bytes:
    Gamma, c, s = ECVRF_decode_proof(pi_string)
    proof_to_hash_domain_separator_front = b'\x03'
    proof_to_hash_domain_separator_back = b'\x00'
    beta_string = sha512(suite_string + proof_to_hash_domain_separator_front + Gamma +
                         proof_to_hash_domain_separator_back).digest()

    return beta_string


def ECVRF_verify(PK_string: bytes, alpha_string: bytes, pi_string: bytes, validate_key=True) -> bytes:
    encode_to_curve_salt = PK_string
    if crypto_core_ristretto255_is_valid_point(PK_string):
        Y = PK_string
    else:
        raise Exception("Invalid point")

    if validate_key and Y == bytes.fromhex(base):
        raise Exception("Invalid point")

    Gamma, c, s = ECVRF_decode_proof(pi_string)

    H = ECVRF_encode_to_curve(encode_to_curve_salt, alpha_string)
    U = crypto_core_ristretto255_sub(crypto_scalarmult_ristretto255_base(s), crypto_scalarmult_ristretto255(c + (16 * b'\x00'), Y))
    V = crypto_core_ristretto255_sub(crypto_scalarmult_ristretto255(s, H),  crypto_scalarmult_ristretto255(c + (16 * b'\x00'), Gamma))
    c1 = ECVRF_challenge_generation(Y, H, Gamma, U, V)
    if c == c1:
        return ECVRF_proof_to_hash(pi_string)
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
    print("hash_string:  " + hash_string.hex())

    return crypto_core_ristretto255_from_hash(hash_string)


# https://github.com/C2SP/C2SP/blob/main/vrf-r255.md
def ECVRF_nonce_generation(SK: bytes, h_string: bytes) -> bytes:
    nonce_generation_domain_separator = b'\x81'
    k_string = sha512(suite_string + nonce_generation_domain_separator + SK + h_string).digest()
    print("k_string: " + k_string.hex())

    return crypto_core_ristretto255_scalar_reduce(k_string)


def ECVRF_challenge_generation(P1: bytes, P2: bytes, P3: bytes, P4: bytes, P5: bytes) -> bytes:
    challenge_generation_domain_separator_front = b'\x02'
    challenge_generation_domain_separator_back = b'\x00'
    s = suite_string + challenge_generation_domain_separator_front + P1 + P2 + P3 + P4 + P5 + \
        challenge_generation_domain_separator_back

    c_string = sha512(s).digest()
    print("c_string: " + c_string.hex())

    return c_string[0:cLen]


print("Test vector (see https://github.com/C2SP/C2SP/blob/main/vrf-r255.md#test-vector)")
SK = '3431c2b03533e280b23232e280b34e2c3132c2b03238e280b23131e280b34500'
alpha = '633273702e6f72672f7672662d72323535'
PK = crypto_scalarmult_ristretto255_base(bytes.fromhex(SK))
print("SK: " + SK)
print("PK: " + PK.hex())
print("alpha: " + alpha)

print("---hash---")
pi = ECVRF_prove(bytes.fromhex(SK), bytes.fromhex(alpha))
print('pi: ' + pi.hex())
beta = ECVRF_proof_to_hash(pi)
print('beta: ' + beta.hex())
print("---verify---")
beta_string = ECVRF_verify(PK, bytes.fromhex(alpha), pi)
print("beta: " + beta_string.hex())

print("-------------------")
print("Test Class ECVRF:")
vrf = ECVRF(bytes.fromhex(SK))
pk = vrf.public_key
print("PK: " + pk.hex())
pi, beta = vrf.hash(bytes.fromhex(alpha))
print('pi: ' + pi.hex())
print('beta: ' + beta.hex())

print(vrf.verify(pk, bytes.fromhex(alpha), pi, beta).hex())
