import pytest
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    rsa,
    ec,
    ed25519,
    ed448,
)

from pki_tools.types import (
    CryptoKeyPair,
    DSAKeyPair,
    RSAKeyPair,
    EllipticCurveKeyPair,
    Ed25519KeyPair,
    Ed448KeyPair,
)
from pki_tools.types.key_pair import (
    CryptoPublicKey,
    CryptoPrivateKey,
    EllipticCurveName,
)


def test_generate_dsa():
    key_pair = DSAKeyPair.generate(key_size=1024)

    print(key_pair.public_key.pem_string)
    print(key_pair.private_key.pem_string)


def test_generate_rsa():
    key_pair = RSAKeyPair.generate(key_size=1024)

    print(key_pair.public_key.pem_string)
    print(key_pair.private_key.pem_string)


def test_crypto_keypair_generate_not_implemented():
    with pytest.raises(NotImplementedError):
        print(CryptoKeyPair.generate())


def test_crypto_keypair_abstract_methods():
    with pytest.raises(TypeError):
        CryptoKeyPair()


@pytest.mark.parametrize(
    "key_pair_cls, args, expected_private, expected_public, expected_dict",
    [
        (
            DSAKeyPair,
            (2048,),
            dsa.DSAPrivateKey,
            dsa.DSAPublicKey,
            {
                "key_size": "2048",
                "generator_g": "",
                "prime_p": "",
                "public_key_y": "",
                "subprime_q": "",
            },
        ),
        (
            RSAKeyPair,
            (2048,),
            rsa.RSAPrivateKey,
            rsa.RSAPublicKey,
            {
                "key_size": "2048",
                "public_exponent_e": "65537",
                "modulus_n": "",
                "private_exponent_d": "",
                "prime_p": "",
                "prime_q": "",
                "dmp1": "",
                "dmq1": "",
                "iqmp": "",
            },
        ),
        (
            EllipticCurveKeyPair,
            (EllipticCurveName.BRAINPOOLP512R1,),
            ec.EllipticCurvePrivateKey,
            ec.EllipticCurvePublicKey,
            {
                "curve_name": "BRAINPOOLP512R1",
                "x_coordinate": "",
                "y_coordinate": "",
            },
        ),
        (
            Ed25519KeyPair,
            (),
            ed25519.Ed25519PrivateKey,
            ed25519.Ed25519PublicKey,
            {"public_bytes": ""},
        ),
        (
            Ed448KeyPair,
            (),
            ed448.Ed448PrivateKey,
            ed448.Ed448PublicKey,
            {"public_bytes": ""},
        ),
    ],
)
def test_keypair_generate(
    key_pair_cls, args, expected_private, expected_public, expected_dict
):
    # test generate
    key_pair = key_pair_cls.generate(*args)

    # validate _string_dict
    str_dict = key_pair.private_key._string_dict()
    for exp_key, exp_val in expected_dict.items():
        if exp_val == "":
            assert str_dict[exp_key] != ""
        else:
            assert str_dict[exp_key] == exp_val

    # Check that dumped keys class
    crypto_private = key_pair.private_key._to_cryptography()
    crypto_public = key_pair.public_key._to_cryptography()
    assert isinstance(crypto_private, expected_private)
    assert isinstance(crypto_public, expected_public)

    # Test getting private/public PEM bytes
    assert "PRIVATE KEY-----" in key_pair.private_key.pem_string
    assert "PUBLIC KEY-----" in key_pair.public_key.pem_string

    # Test loading from crypto
    CryptoPrivateKey.from_cryptography(crypto_private)
    CryptoPublicKey.from_cryptography(crypto_public)


def test_key_pair_from_cryptography():
    key_pair = RSAKeyPair.generate()
    crypto_public = key_pair.public_key._to_cryptography()
    crypto_private = key_pair.private_key._to_cryptography()

    assert isinstance(crypto_public, rsa.RSAPublicKey)
    assert isinstance(crypto_private, rsa.RSAPrivateKey)
