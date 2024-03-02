from loguru import logger

from .types import (
    Chain,
    Certificate,
    Certificates,
    Extensions,
    Name,
    RevokeMode,
    SignatureAlgorithm,
    HashAlgorithm,
    HashAlgorithmName,
    Validity,
    CertificateSigningRequest,
    CertificateRevocationList,
    DSAKeyPair,
    RSAKeyPair,
    EllipticCurveKeyPair,
    Ed25519KeyPair,
    Ed448KeyPair,
    SHA1,
    SHA512_224,
    SHA512_256,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    SHAKE128,
    SHAKE256,
    MD5,
    BLAKE2b,
    BLAKE2s,
    SM3,
)

from .exceptions import (
    ExtensionMissing,
    Error,
    OcspInvalidResponseStatus,
    OcspFetchFailure,
    OcspIssuerFetchFailure,
    RevokeCheckFailed,
    NotCompleteChain,
    CertIssuerMissingInChain,
    CertExpired,
    InvalidSignedType,
    SignatureVerificationFailed,
    CertLoadError,
)

from .crl import _is_revoked
from .ocsp import _is_revoked_multiple_issuers


def is_revoked(
    cert: Certificate,
    chain: Chain,
    crl_cache_seconds: int = 3600,
    ocsp_res_cache_seconds: int = 3600,
    revoke_mode: RevokeMode = RevokeMode.OCSP_FALLBACK_CRL,
) -> bool:
    """
    Checks if a certificate is revoked using OCSP extension and/or
    CRL extension.

    By default, the OCSP is checked first with a fallback to CRL. If you
    only want to check OCSP or only CRL set the "revoke_mode" to either
    RevokeMode.OCSP_ONLY or RevokeMode.CRL_ONLY

    Arguments:
        cert -- The
        [Certificates](https://pki-tools.fulder.dev/pki_tools/types/certificates)
        certificate to check revocation for.
        chain -- The CA chain including one or more certificates and
        the issuer of the `cert`, signer of the OCSP response and CRL
        issuer. See
        [types.Chain](https://pki-tools.fulder.dev/pki_tools/types/chain)
        for examples how the chain can be created
        crl_cache_seconds -- [CRL Only] Specifies how long the CRL should
        be cached, default is 1 hour.
        ocsp_res_cache_seconds -- [OCSP Only] Specifies how long the OCSP
        response should be cached, default is 1 hour.
        revoke_mode -- A
        [types.RevokeMode](https://pki-tools.fulder.dev/pki_tools/types/enums/#revokemode)
        specifying how to check for revocation, default is OCSP with
        CRL fallback
    Returns:
        True if the certificate is revoked, False otherwise
    Raises:
        [exceptions.SignatureVerificationFailed](https://pki-tools.fulder.dev/pki_tools/exceptions/#signatureverificationfailed)
        -- When the Chain contains more than one certificate and
        the trust fails either because of some certificate has expired
        or some signature in the chain is invalid

        [exceptions.RevokeCheckFailed](https://pki-tools.fulder.dev/pki_tools/exceptions/#revokecheckfailed)
        -- When both OCSP and CRL checks fail
    """
    return is_revoked_multiple_issuers(
        cert,
        chain,
        chain,
        chain,
        crl_cache_seconds=crl_cache_seconds,
        ocsp_res_cache_seconds=ocsp_res_cache_seconds,
        revoke_mode=revoke_mode,
    )


def is_revoked_multiple_issuers(
    cert: Certificate,
    cert_issuer: Chain,
    ocsp_issuer: Chain,
    crl_issuer: Chain,
    crl_cache_seconds: int = 3600,
    ocsp_res_cache_seconds: int = 3600,
    revoke_mode: RevokeMode = RevokeMode.OCSP_FALLBACK_CRL,
):
    """
    Checks if a certificate is revoked first using the OCSP extension and then
    the CRL extensions.

    Note that OCSP has precedence over CRL meaning that if OCSP check is
    successful this function will return the bool without checking CRL.

    Otherwise, if OCSP check fails, CRL will be tried next.

    Arguments:
        cert -- The
        [Certificates](https://pki-tools.fulder.dev/pki_tools/types/certificates)
        certificate to check revocation for.
        cert_issuer -- The CA chain including one or more certificates and
        the issuer of the `cert`. See
        [types.Chain](https://pki-tools.fulder.dev/pki_tools/types/#chain)
        for examples how the chain can be created
        ocsp_issuer -- The CA chain including one or more certificates used
        for signing of the OCSP response
        crl_issuer -- The CA chain including one or more certificates used
        for signing the CRL
        crl_cache_seconds -- [CRL Only] Specifies how long the CRL should be
        cached, default is 1 hour.
        ocsp_res_cache_seconds -- [OCSP Only] Specifies how long the OCSP
        response should be cached, default is 1 hour.
        revoke_mode -- A
        [types.RevokeMode](https://pki-tools.fulder.dev/pki_tools/types/enums/#revokemode)
        specifying how to check for revocation, default is OCSP with
        CRL fallback
    Returns:
        True if the certificate is revoked, False otherwise
    Raises:
        [exceptions.SignatureVerificationFailed](https://pki-tools.fulder.dev/pki_tools/exceptions/#signatureverificationfailed)
        -- When the Chain contains more than one certificate and
        the trust fails either because of some certificate has expired
        or some signature in the chain is invalid

        [exceptions.RevokeCheckFailed](https://pki-tools.fulder.dev/pki_tools/exceptions/#revokecheckfailed)
        -- When OCSP and/or CRL checks fail(s)
    """
    if not revoke_mode == RevokeMode.CRL_ONLY:
        try:
            return _is_revoked_multiple_issuers(
                cert,
                cert_issuer,
                ocsp_issuer,
                ocsp_res_cache_seconds=ocsp_res_cache_seconds,
            )
        except (
            ExtensionMissing,
            OcspInvalidResponseStatus,
            OcspFetchFailure,
            OcspIssuerFetchFailure,
        ) as e:
            if revoke_mode == RevokeMode.OCSP_ONLY:
                err_msg = "OCSP revoke check failed"
                logger.bind(exceptionType=type(e).__name__).error(err_msg)
                raise RevokeCheckFailed(err_msg) from None

            err_msg = "OCSP revoke check failed, trying CRL next"
            logger.bind(exceptionType=type(e).__name__).debug(err_msg)

    try:
        return _is_revoked(cert, crl_issuer, crl_cache_seconds)
    except Error as e:
        err_message = "Revoke checks failed"
        logger.bind(exceptionType=type(e).__name__).error(err_message)
        raise RevokeCheckFailed(err_message) from None
