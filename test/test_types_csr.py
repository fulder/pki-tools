import os

import pytest

from pki_tools import Name
from pki_tools.exceptions import LoadError
from pki_tools.types import RSAKeyPair
from pki_tools.types.csr import CertificateSigningRequest
from conftest import CURRENT_DIR
from pki_tools.types.signature_algorithm import (
    SignatureAlgorithm,
    HashAlgorithmName,
    HashAlgorithm,
    PKCS1v15Padding,
)


def test_csr_from_cryptography(crypto_csr, key_pair, dsa_test):
    if dsa_test:
        pytest.skip("DSA not supported")
    CertificateSigningRequest.from_cryptography(crypto_csr)


def test_csr_from_pem_string_invalid_data():
    with pytest.raises(LoadError):
        CertificateSigningRequest.from_pem_string("BAD_PEM_DATA")


def test_csr_from_pem_string_with_space(csr, dsa_test):
    if dsa_test:
        pytest.skip("DSA not supported")
    CertificateSigningRequest.from_pem_string("\n\n" + csr.pem_string + "\n")


def test_certificate_save_and_read_file(csr, dsa_test):
    if dsa_test:
        pytest.skip("DSA not supported")

    cert = CertificateSigningRequest.from_pem_string(csr.pem_string)

    file_path = os.path.join(CURRENT_DIR, "tmp.pem")
    cert.to_file(file_path)

    new_cert = CertificateSigningRequest.from_file(file_path)

    os.remove(file_path)

    assert cert.pem_string == new_cert.pem_string


def test_init_csr():
    hash_alg = HashAlgorithm(
        name=HashAlgorithmName.SHA512, padding=PKCS1v15Padding()
    )
    csr = CertificateSigningRequest(
        subject=Name(ou=["MY OU"]),
    )
    csr.sign(RSAKeyPair.generate(), SignatureAlgorithm(algorithm=hash_alg))
