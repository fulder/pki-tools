import os

import pytest

from pki_tools.exceptions import CsrLoadError
from pki_tools.types.csr import CertificateSigningRequest
from conftest import CURRENT_DIR


def test_csr_from_cryptography(crypto_csr):
    CertificateSigningRequest.from_cryptography(crypto_csr)



def test_csr_from_pem_string_invalid_data():
    with pytest.raises(CsrLoadError):
        CertificateSigningRequest.from_pem_string("BAD_PEM_DATA")


def test_csr_from_pem_string_with_space(csr):
    CertificateSigningRequest.from_pem_string("\n\n" + csr.pem_string + "\n")


def test_certificate_save_and_read_file(csr):
    cert = CertificateSigningRequest.from_pem_string(csr.pem_string)

    file_path = os.path.join(CURRENT_DIR, "tmp.pem")
    cert.to_file(file_path)

    new_cert = CertificateSigningRequest.from_file(file_path)

    os.remove(file_path)

    assert cert.pem_string == new_cert.pem_string