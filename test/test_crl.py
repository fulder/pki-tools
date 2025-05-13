import pytest

from pki_tools.exceptions import (
    LoadError,
    FetchFailure,
)
from pki_tools.crl import _is_revoked
from conftest import _create_crl
from pki_tools.exceptions import CrlIdpInvalid


def test_crl_fetch_error(mocked_requests_get, cert, chain):
    mocked_requests_get.return_value.status_code = 503

    with pytest.raises(FetchFailure):
        _is_revoked(cert, chain)


def test_crl_load_failure(mocked_requests_get, cert, chain):
    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = "INVALID_DATA".encode()

    with pytest.raises(LoadError):
        _is_revoked(cert, chain)


def test_crl(mocked_requests_get, cert, chain, crl):
    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = crl.der_bytes

    result = _is_revoked(cert, chain)

    assert result is False


def test_invalid_crl_idp(mocked_requests_get, cert, chain, key_pair):
    crl = _create_crl(key_pair, [], idp_uri="invalid_uri")
    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = crl.der_bytes

    with pytest.raises(CrlIdpInvalid):
        _is_revoked(cert, chain)
