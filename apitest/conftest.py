import ssl

import pytest

from pki_tools import Chain, Certificate


@pytest.fixture
def chain() -> Chain:
    return Chain.from_uri(
        [
            "https://letsencrypt.org/certs/isrgrootx1.pem",
            "https://letsencrypt.org/certs/lets-encrypt-r3.pem",
        ]
    )


@pytest.fixture
def revoked_cert_ocsp() -> Certificate:
    return Certificate.from_server(
        "https://revoked-isrgrootx1.letsencrypt.org"
    )


@pytest.fixture
def revoked_crl_chain() -> Chain:
    return Chain.from_uri(["https://letsencrypt.org/certs/isrgrootx1.pem"])


@pytest.fixture
def revoked_crl_cert() -> Certificate:
    return Certificate.from_uri(
        "https://letsencrypt.org/certs/lets-encrypt-r3.pem"
    )


@pytest.fixture
def cert() -> Certificate:
    hostname = "valid-isrgrootx1.letsencrypt.org"
    cert_pem = ssl.get_server_certificate((hostname, 443))

    return Certificate.from_pem_string(cert_pem)
