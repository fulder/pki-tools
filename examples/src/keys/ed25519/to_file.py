private_pem = """
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIK1Rmqg3vSeNU/VcGCcp6v9jg2Wc4oQOsZUX7UboRrIL
-----END PRIVATE KEY-----
"""
public_pem = """
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAwz9uDUJ3qeYcok1CoMAbfiJrZT7PlT3wtLZwf+wlhho=
-----END PUBLIC KEY-----
"""

from pki_tools import Ed25519KeyPair, Ed25519PublicKey, Ed25519PrivateKey

key_pair = Ed25519KeyPair(
    public_key=Ed25519PublicKey.from_pem_string(public_pem),
    private_key=Ed25519PrivateKey.from_pem_string(private_pem),
)

key_pair.public_key.to_file("out_public.pem")
key_pair.private_key.to_file("out_private.pem")
