import pytest


from pki_tools.exceptions import (
    CrlFetchFailure,
    CrlLoadError,
)
from pki_tools.crl import is_revoked


def test_crl_fetch_error(mocked_requests_get, cert):
    mocked_requests_get.return_value.status_code = 503

    with pytest.raises(CrlFetchFailure):
        is_revoked(cert)


def test_crl_load_failure(mocked_requests_get, cert):
    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = "INVALID_DATA"

    with pytest.raises(CrlLoadError):
        is_revoked(cert)
