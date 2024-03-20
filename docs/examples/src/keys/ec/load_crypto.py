from cryptography.hazmat.primitives import serialization

private_key_pem = b"""
-----BEGIN EC PRIVATE KEY-----
MF8CAQEEGKjPz1HxOsCzWDldL2lBRkhNn8BeANbriaAKBggqhkjOPQMBAaE0AzIA
BJ32je0cT4KuCA13aM56xkUnEFGukuHAMU6cWJhInPl95dkcRhs+U8ZrUGO9jFaR
kg==
-----END EC PRIVATE KEY-----
"""
public_key_pem = b"""
-----BEGIN PUBLIC KEY-----
MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEnfaN7RxPgq4IDXdoznrGRScQUa6S
4cAxTpxYmEic+X3l2RxGGz5TxmtQY72MVpGS
-----END PUBLIC KEY-----
"""

crypto_public_key = serialization.load_pem_public_key(public_key_pem)
crypto_private_key = serialization.load_pem_private_key(
    private_key_pem, password=None
)

from pki_tools import EllipticCurveKeyPair, EllipticCurvePublicKey, EllipticCurvePrivateKey

key_pair = EllipticCurveKeyPair(
    public_key=EllipticCurvePublicKey.from_cryptography(crypto_public_key),
    private_key=EllipticCurvePrivateKey.from_cryptography(crypto_private_key),
)

print(key_pair)
