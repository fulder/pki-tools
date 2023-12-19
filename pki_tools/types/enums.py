from enum import Enum


class RevokeMode(Enum):
    OCSP_FALLBACK_CRL = "OCSP_FALLBACK_CRL"
    OCSP_ONLY = "OCSP_ONLY"
    CRL_ONLY = "CRL_ONLY"
