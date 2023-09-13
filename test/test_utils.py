import pytest

from pki_tools.utils import CertLoadError, cert_from_pem


def test_cert_load_error():
    with pytest.raises(CertLoadError):
        cert_from_pem("BAD_PEM_DATA")
