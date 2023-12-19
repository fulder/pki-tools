import pki_tools
from pki_tools import Certificate, Chain, RevokeMode


def test_revoked(revoked_cert, chain):
    assert pki_tools.is_revoked(revoked_cert, chain)


def test_revoked_only_ocsp(revoked_cert, chain):
    assert pki_tools.is_revoked(revoked_cert, chain, revoke_mode=RevokeMode.OCSP_ONLY)


def test_not_revoked(cert, chain):
    assert not pki_tools.is_revoked(cert, chain)


def test_crl(intermediate_ca_pem, root_ca_pem):
    cert = Certificate.from_pem_string(intermediate_ca_pem)
    chain = Chain.from_pem_string(root_ca_pem)
    assert not pki_tools.is_revoked(cert, chain)
