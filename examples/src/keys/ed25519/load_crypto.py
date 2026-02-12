from cryptography.hazmat.primitives import serialization

private_key_pem = b"""
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIK1Rmqg3vSeNU/VcGCcp6v9jg2Wc4oQOsZUX7UboRrIL
-----END PRIVATE KEY-----
"""
public_key_pem = b"""
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAwz9uDUJ3qeYcok1CoMAbfiJrZT7PlT3wtLZwf+wlhho=
-----END PUBLIC KEY-----
"""

crypto_public_key = serialization.load_pem_public_key(public_key_pem)
crypto_private_key = serialization.load_pem_private_key(
    private_key_pem, password=None
)

from pki_tools import Ed25519KeyPair, Ed25519PublicKey, Ed25519PrivateKey

key_pair = Ed25519KeyPair(
    public_key=Ed25519PublicKey.from_cryptography(crypto_public_key),
    private_key=Ed25519PrivateKey.from_cryptography(crypto_private_key),
)

print(key_pair)
