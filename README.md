# pyvrf-r255
**WARNING:** This is just a PoC. Use at your own risk. <br />
This is a simple python implementation of <br />
[c2sp.org/vrf-r255](https://github.com/C2SP/C2SP/blob/main/vrf-r255.md). <br /> <br />
It uses [pysodium](https://github.com/stef/pysodium) for all Ristretto255 functions. Therefore [libsodium](https://github.com/jedisct1/libsodium) must be pre-installed.
## Usage:
```
# Use your own private Key
vrf = ECVRF(bytes.fromhex('3431c2b03533e280b23232e280b34e2c3132c2b03238e280b23131e280b34500'))

# or create a random private Key
vrf = ECVRF.random_key()

# Get the secret Key
sk = vrf.secret_key

# Get the public Key
pk = vrf.public_key

# Get proof and hash for a message
pi, beta = vrf.hash(b'bla')

# Verify
print(vrf.verify(pk, b'bla', pi, beta))
```
