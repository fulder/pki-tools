import ssl

import httpx
import pytest

from pki_tools import Chain, Certificate


@pytest.fixture
def root_ca_pem():
    ret = httpx.get("https://letsencrypt.org/certs/isrgrootx1.pem")
    return ret.text


@pytest.fixture
def intermediate_ca_pem():
    ret = httpx.get("https://letsencrypt.org/certs/lets-encrypt-r3.pem")
    return ret.text


@pytest.fixture
def chain(intermediate_ca_pem, root_ca_pem):
    return Chain.from_pem_string(intermediate_ca_pem + root_ca_pem)


@pytest.fixture
def revoked_cert():
    return Certificate.from_uri("https://revoked-isrgrootx1.letsencrypt.org")


@pytest.fixture
def cert():
    hostname = "valid-isrgrootx1.letsencrypt.org"
    cert_pem = ssl.get_server_certificate((hostname, 443))

    return Certificate.from_pem_string(cert_pem)
