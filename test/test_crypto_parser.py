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
def test_init_crypto_parser_funcs(init_crypto_parsers, parser_name, dsa_test):
    if parser_name == "CertificateSigningRequest" and dsa_test:
        pytest.skip("DSA not supported")

    crypto_parser = init_crypto_parsers[parser_name]

    # Test dump and load from DER
    crypto_parser.to_file("test.der", encoding=Encoding.DER)
    getattr(crypto_parser.__class__, "from_file")(
        "test.der", encoding=Encoding.DER
    )

    # Test dump and load from PEM
    crypto_parser.to_file("test.pem", encoding=Encoding.PEM)
    getattr(crypto_parser.__class__, "from_file")(
        "test.pem", encoding=Encoding.PEM
    )
