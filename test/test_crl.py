import pytest


from pki_tools.exceptions import (
    CrlFetchFailure,
    CrlLoadError,
)
from pki_tools.crl import _is_revoked


def test_crl_fetch_error(mocked_requests_get, cert, chain):
    mocked_requests_get.return_value.status_code = 503

    with pytest.raises(CrlFetchFailure):
        _is_revoked(cert, chain)


def test_crl_load_failure(mocked_requests_get, cert, chain):
    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = "INVALID_DATA"

    with pytest.raises(CrlLoadError):
        _is_revoked(cert, chain)
