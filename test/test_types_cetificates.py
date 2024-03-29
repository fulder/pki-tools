import os

from conftest import CURRENT_DIR
from pki_tools import Certificates


def test_certificates_from_pem_string(cert_pem_string):
    Certificates.from_pem_string(cert_pem_string)


def test_certificates_save_and_read_file(cert_pem_string, key_pair_name):
    two_certs = f"{cert_pem_string}\n{cert_pem_string}"
    certs = Certificates.from_pem_string(two_certs)

    file_name = f"{key_pair_name}_cert.pem"
    file_path = os.path.join(CURRENT_DIR, file_name)
    certs.to_file(file_path)

    new_certs = Certificates.from_file(file_path)

    os.remove(file_path)

    assert certs.pem_string == new_certs.pem_string


def test_certificates_from_uri(mocked_requests_get, cert_pem_string):
    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.text = cert_pem_string

    Certificates.from_uri(["http://TEST_URI"])


def test_certificates_from_uri_multiple(mocked_requests_get, cert_pem_string):
    mocked_requests_get.return_value.status_code = 200
    certs = cert_pem_string + "\n" + cert_pem_string
    mocked_requests_get.return_value.text = certs

    certs = Certificates.from_uri(["http://TEST_URI"])
    assert len(certs.certificates) == 2
    assert certs.certificates[0].pem_string == cert_pem_string
