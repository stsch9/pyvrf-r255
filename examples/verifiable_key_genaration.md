
# Verifiable Key generation

**Warning:** Nobody has reviewed this example and the assertions.

Sometimes it is necessary to be able to prove to someone who generated a key pair.
You can use your secret key `sk` and the VRF output to generate a key pair. With prior knowledge of the public key `pk` and `alpha`, someone can use `pi` to prove that he generated the keypair.

Signatures do not work because they can simply be replaced by a signature of another user. 
Creating keys from the output of hash functions and using the hash input as proof does not work either,
because this proof can only be provided once and then any other person who knows the input can provide the proof.

This is true because the following assertion holds:

For fixed `alpha` and `beta` it is infeasible to find two different keypairs `(sk, pk)`, `(sk_2, pk_2)` and two proofs `pi` and `pi_2` such that

```
VRF_verify(pk, alpha, pi) = ("VALID", beta)
VRF_verify(pk_2, alpha, pi_2) = ("VALID", beta)
```

**Proof**:
Assume that we have found a second keypair `(sk_2, pk_2) != (sk, pk)` and a proof `pi_2 such that 
```
VRF_verify(pk_2, alpha, pi_2) = ("VALID", beta)
```

Let
```
pi_3, beta_3 = VRF_hash(sk_2, alpha)
```

Then `beta != beta_3` since `sk != sk_2` and due the randomness.

Therefore
```
VRF_verify(pk_2, alpha, pi_2) = ("VALID", beta)
VRF_verify(pk_2, alpha, pi_3) = ("VALID", beta_3)
beta != beta_3
```
 
This is a contradiction to the full-uniqueness property, see https://www.rfc-editor.org/rfc/rfc9381.html#name-full-uniqueness

## Code
```
def generate_key_pair(sk, info=b"derive key pair"):
    alpha = randombytes(32)
    pi, beta = VRF_hash(SK, alpha)
    seed = HKDF-Expand(beta, info) # possibly not necessary
    PK, SK = derive_deterministic_keypair_from_seed(seed)

    return PK, SK, alpha, pi
```