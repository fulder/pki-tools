from enum import Enum


class RevokeMode(Enum):
    """
    Specifies in what precedence and protocols (OCSP, CRL)
    to check revocation status of a certificate
    """
    OCSP_FALLBACK_CRL = "OCSP_FALLBACK_CRL"
    OCSP_ONLY = "OCSP_ONLY"
    CRL_ONLY = "CRL_ONLY"
