private_pem = """
-----BEGIN PRIVATE KEY-----
MEcCAQAwBQYDK2VxBDsEOddX4ESZ5SsmiX/VMUPbnpPs/OOG4/zGvm4H5mN3nDTn
aueR56mFimzXxc7tj3z+N1lmNeO23ZNFPA==
-----END PRIVATE KEY-----
"""
public_pem = """
-----BEGIN PUBLIC KEY-----
MEMwBQYDK2VxAzoAfCdaj7HXSPMqW+Tl+lXEzItOzK2AoZjkvcCMR+gepngd0mDy
KbC4U+fVnxnbf1UuJxFiARSUjUWA
-----END PUBLIC KEY-----
"""

from pki_tools import Ed448KeyPair, Ed448PublicKey, Ed448PrivateKey

key_pair = Ed448KeyPair(
    public_key=Ed448PublicKey.from_pem_string(public_pem),
    private_key=Ed448PrivateKey.from_pem_string(private_pem),
)

key_pair.public_key.to_file("out_public.pem")
key_pair.private_key.to_file("out_private.pem")
