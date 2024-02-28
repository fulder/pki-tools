import pytest
from cryptography.hazmat.primitives.asymmetric import dsa, rsa, ec, ed25519, \
    ed448

from pki_tools.types import (
    CryptoKeyPair, DSAKeyPair, RSAKeyPair, EllipticCurveKeyPair,
    Ed25519KeyPair, Ed448KeyPair, KeyPair
)


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
                (2048, ),
                dsa.DSAPrivateKey,
                dsa.DSAPublicKey,
                {
                    "key_size": "2048",
                    "generator_g": "",
                    "prime_p": "",
                    "public_key_y": "",
                    "subprime_q": ""
                }
        ),
        (
                RSAKeyPair,
                (2048, ),
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
                    "iqmp": ""
                }
        ),
        (
                EllipticCurveKeyPair,
                ("SECP192R1", ) ,
                ec.EllipticCurvePrivateKey,
                ec.EllipticCurvePublicKey,
                {
                    "curve_name": "SECP192R1",
                    "x_coordinate": "",
                    "y_coordinate": "",
                    "private_key_d": ""
                }
        ),
        (
                Ed25519KeyPair,
                (),
                ed25519.Ed25519PrivateKey,
                ed25519.Ed25519PublicKey,
                {"public_bytes": ""}
        ),
        (
                Ed448KeyPair,
                (),
                ed448.Ed448PrivateKey,
                ed448.Ed448PublicKey,
                {"public_bytes": ""}
        )
    ]
)
def test_keypair_generate(
        key_pair_cls, args, expected_private, expected_public, expected_dict
):
    # test generate
    key_pair = key_pair_cls.generate(*args)

    # validate _string_dict
    str_dict = key_pair._string_dict()
    for exp_key, exp_val in expected_dict.items():
        if exp_val == "":
            assert str_dict[exp_key] != ""
        else:
            assert str_dict[exp_key] == exp_val

    # Check that dumped key is a private crypto class
    assert isinstance(key_pair._to_cryptography(), expected_private)

    # Test dumping public crypto key and parsing it again
    public_crypto_key = key_pair._to_cryptography().public_key()
    key_pair = key_pair_cls.from_cryptography(public_crypto_key)
    assert isinstance(key_pair._to_cryptography(), expected_public)



def test_key_pair_from_cryptography():
    crypto_rsa = RSAKeyPair.generate()._to_cryptography()

    key_pair = KeyPair.from_cryptography(crypto_rsa)
    assert isinstance(key_pair._to_cryptography(), rsa.RSAPrivateKey)