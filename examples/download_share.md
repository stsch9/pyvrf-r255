Suppose that the public and secret VRF keys `(PK, SK)` were generated correctly, where `PK` is known and `SK` is unknown. Then it is impossible to find `alpha`, `beta` and `pi` such that
```
VRF_verify(pk, alpha, pi) = ("VALID", beta)
```
**Proof:**
Suppose an adversary can find `alpha`, `beta` and `pi` such that
```
VRF_verify(pk, alpha, pi) = ("VALID", beta)
```
Let
```
VRF_hash(SK, alpha) = pi_2, beta_2
```
Then
```
VRF_verify(pk, alpha, pi) = ("VALID", beta)
VRF_verify(pk, alpha, pi_2) = ("VALID", beta_2)
```
Due to [Full Collision Resistance](https://www.rfc-editor.org/rfc/rfc9381.html#name-full-collision-resistance) it holds
```
beta = beta_2
```
Therefore an adversary has found `alpha` and `beta` such that
```
VRF_hash(SK, alpha) = pi_2, beta
```
This is a contradiction to the statement:
> Pseudorandomness ensures that the VRF hash output beta (without its corresponding VRF proof pi) on any adversarially chosen "target" VRF input alpha looks indistinguishable from random for any adversary who does not know the VRF secret key SK.

(see [Full Pseudorandomness or Selective Pseudorandomness](https://www.rfc-editor.org/rfc/rfc9381.html#name-full-pseudorandomness-or-se)). 
