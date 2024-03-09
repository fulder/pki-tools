import pki_tools
from pki_tools import RevokeMode


def test_revoked(revoked_cert_ocsp, chain):
    assert pki_tools.is_revoked(revoked_cert_ocsp, chain)


def test_revoked_only_ocsp(revoked_cert_ocsp, chain):
    assert pki_tools.is_revoked(
        revoked_cert_ocsp, chain, revoke_mode=RevokeMode.OCSP_ONLY
    )


def test_revoked_crl_only(revoked_crl_cert, revoked_crl_chain):
    assert not pki_tools.is_revoked(
        revoked_crl_cert, revoked_crl_chain, revoke_mode=RevokeMode.CRL_ONLY
    )


def test_not_revoked(cert, chain):
    assert not pki_tools.is_revoked(cert, chain)
