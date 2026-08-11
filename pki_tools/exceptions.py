class Error(Exception):
    """
    Error is the base pki_tools exception
    """


class ExtensionMissing(Error):
    """
    ExtensionMissing
    """


class OcspFetchFailure(Error):
    """
    OcspFetchFailure
    """


class FetchFailure(Error):
    """
    FetchFailure
    """


class OcspInvalidResponseStatus(Error):
    """
    OcspInvalidResponseStatus
    """


class OcspIssuerFetchFailure(Error):
    """
    OcspIssuerFetchFailure
    """


class LoadError(Error):
    """
    Risen when a IoCryptoParser implementing class could not be
    loaded properly.
    """


class RevokeCheckFailed(Error):
    """
    RevokeCheckFailed
    """


class CertIssuerMissingInChain(Error):
    """
    CertIssuerMissingInChain
    """


class NotCompleteChain(Error):
    """
    NotCompleteChain
    """


class CertExpired(Error):
    """
    CertExpired
    """


class SignatureVerificationFailed(Error):
    """
    SignatureVerificationFailed
    """


class InvalidSignedType(Error):
    """
    InvalidSignedType
    """


class MissingInit(Error):
    """
    Risen when the
    [InitCryptoParser][pki_tools.types.crypto_parser.InitCryptoParser]
    has not been initialized.
    """


class MissingBlockSize(Error):
    """
    MissingBlockSize
    """


class CrlIdpInvalid(Error):
    """
    CrlIdpInvalid
    """
