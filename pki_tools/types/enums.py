from enum import Enum


class RevokeMode(Enum):
    """
    Specifies in what precedence and protocols (OCSP, CRL)
    to check revocation status of a certificate

    Attributes:
        OCSP_FALLBACK_CRL -- Check OCSP first and fallback to CRL if it fails
        OCSP_ONLY -- Only check OCSP and ignore CRL
        CRL_ONLY -- Only check CRL and ignore OCSP
    """

    OCSP_FALLBACK_CRL = "OCSP_FALLBACK_CRL"
    OCSP_ONLY = "OCSP_ONLY"
    CRL_ONLY = "CRL_ONLY"
