import os

import pytest

from pki_tools.types.crypto_parser import Encoding


@pytest.mark.parametrize(
    "parser_name",
    [
        "Certificate",
        "CertificateSigningRequest",
        "CertificateRevocationList",
        "OCSPResponse",
        "OCSPRequest",
        "RSAPublicKey",
        "RSAPrivateKey",
        "DSAPrivateKey",
        "DSAPublicKey",
        "Ed25519PrivateKey",
        "Ed25519PublicKey",
        "Ed448PrivateKey",
        "Ed448PublicKey",
        "EllipticCurvePrivateKey",
        "EllipticCurvePublicKey",
    ],
)
def test_init_crypto_parser_funcs(
    init_crypto_parsers, parser_name, dsa_test, key_pair_name
):
    if parser_name == "CertificateSigningRequest" and dsa_test:
        pytest.skip("DSA not supported")

    crypto_parser = init_crypto_parsers[parser_name]

    # Test dump and load from DER
    file_name = f"{parser_name}_{key_pair_name}_test.der"
    crypto_parser.to_file(file_name, encoding=Encoding.DER)
    getattr(crypto_parser.__class__, "from_file")(
        file_name, encoding=Encoding.DER
    )
    os.unlink(file_name)

    # Test dump and load from PEM
    file_name = f"{parser_name}_{key_pair_name}_test.pem"
    crypto_parser.to_file(file_name, encoding=Encoding.PEM)
    getattr(crypto_parser.__class__, "from_file")(
        file_name, encoding=Encoding.PEM
    )
    os.unlink(file_name)
