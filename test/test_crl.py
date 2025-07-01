import pytest

from pki_tools.exceptions import (
    LoadError,
    FetchFailure,
)
from pki_tools.crl import _is_revoked, _compare_cdp_and_idp
from conftest import _create_crl
from pki_tools.exceptions import CrlIdpInvalid
from unittest.mock import Mock

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
    mock_response_503 = Mock()
    mock_response_503.status_code = 503

    mock_response_200 = Mock()
    mock_response_200.status_code = 200
    mock_response_200.content = crl.der_bytes

    mocked_requests_get.side_effect = [mock_response_503, mock_response_200]

    result = _is_revoked(cert, chain)

    assert result is False


def test_invalid_crl_idp(mocked_requests_get, cert, chain, key_pair):
    crl = _create_crl(key_pair, [], idp_uri="invalid_uri")
    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = crl.der_bytes

    with pytest.raises(CrlIdpInvalid):
        _is_revoked(cert, chain)


def test_compare_cdp_and_idp():
    ret = _compare_cdp_and_idp(
        "https://my.domain.com/crl.pem",
        "https://my.domain.com/crl.pem",
    )
    assert ret is True


def test_compare_cdp_and_idp_different():
    ret = _compare_cdp_and_idp(
        "https://my.domain.com/crl.pem",
        "https://my.domain.com/other_crl.pem",
    )
    assert ret is False


def test_compare_cdp_and_idp_different_scheme():
    ret = _compare_cdp_and_idp(
        "https://my.domain.com/crl.pem",
        "http://my.domain.com/crl.pem",
    )
    assert ret is False


def test_compare_cdp_and_idp_different_host():
    ret = _compare_cdp_and_idp(
        "https://my.domain.com/crl.pem",
        "https://other.domain.com/crl.pem",
    )
    assert ret is False


def test_compare_cdp_and_idp_same_ip():
    ret = _compare_cdp_and_idp(
        "https://localhost/crl.pem", "https://127.0.0.1/crl.pem"
    )
    assert ret is True


def test_compare_cdp_and_idp_same_domains():
    ret = _compare_cdp_and_idp(
        "https://example.com/crl.pem",
        "https://example2.com/crl.pem",
        [["aa.com", "bb.com"], ["example.com", "example2.com"]],
    )
    assert ret is True
