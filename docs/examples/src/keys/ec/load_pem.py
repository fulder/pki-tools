private_pem = """
-----BEGIN EC PRIVATE KEY-----
MF8CAQEEGKjPz1HxOsCzWDldL2lBRkhNn8BeANbriaAKBggqhkjOPQMBAaE0AzIA
BJ32je0cT4KuCA13aM56xkUnEFGukuHAMU6cWJhInPl95dkcRhs+U8ZrUGO9jFaR
kg==
-----END EC PRIVATE KEY-----
"""
public_pem = """
-----BEGIN PUBLIC KEY-----
MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEnfaN7RxPgq4IDXdoznrGRScQUa6S
4cAxTpxYmEic+X3l2RxGGz5TxmtQY72MVpGS
-----END PUBLIC KEY-----
"""

from pki_tools import (
    EllipticCurveKeyPair,
    EllipticCurvePublicKey,
    EllipticCurvePrivateKey,
)

key_pair = EllipticCurveKeyPair(
    public_key=EllipticCurvePublicKey.from_pem_string(public_pem),
    private_key=EllipticCurvePrivateKey.from_pem_string(private_pem),
)

print(key_pair)
