import os

from conftest import CURRENT_DIR
from pki_tools import Certificates


def test_certificates_from_pem_string(cert_pem_string):
    Certificates.from_pem_string(cert_pem_string)


def test_certificates_save_and_read_file(cert_pem_string):
    two_certs = f"{cert_pem_string}\n{cert_pem_string}"
    certs = Certificates.from_pem_string(two_certs)

    file_path = os.path.join(CURRENT_DIR, "tmp.pem")
    certs.to_file(file_path)

    new_certs = Certificates.from_file(file_path)

    os.remove(file_path)

    assert certs.pem_string == new_certs.pem_string


def test_certificates_from_uri(mocked_requests_get, cert_pem_string):
    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.text = cert_pem_string

    Certificates.from_uri("http://TEST_URI")
