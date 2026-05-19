from cryptography.hazmat.primitives import serialization

private_key_pem = b"""
-----BEGIN PRIVATE KEY-----
MEcCAQAwBQYDK2VxBDsEOddX4ESZ5SsmiX/VMUPbnpPs/OOG4/zGvm4H5mN3nDTn
aueR56mFimzXxc7tj3z+N1lmNeO23ZNFPA==
-----END PRIVATE KEY-----
"""
public_key_pem = b"""
-----BEGIN PUBLIC KEY-----
MEMwBQYDK2VxAzoAfCdaj7HXSPMqW+Tl+lXEzItOzK2AoZjkvcCMR+gepngd0mDy
KbC4U+fVnxnbf1UuJxFiARSUjUWA
-----END PUBLIC KEY-----
"""

crypto_public_key = serialization.load_pem_public_key(public_key_pem)
crypto_private_key = serialization.load_pem_private_key(
    private_key_pem, password=None
)

from pki_tools import Ed448KeyPair, Ed448PublicKey, Ed448PrivateKey

key_pair = Ed448KeyPair(
    public_key=Ed448PublicKey.from_cryptography(crypto_public_key),
    private_key=Ed448PrivateKey.from_cryptography(crypto_private_key),
)

print(key_pair)
