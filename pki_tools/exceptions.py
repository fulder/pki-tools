class Error(Exception):
    """
    Error is the base pki_tools exception
    """

    pass


class ExtensionMissing(Error):
    """
    ExtensionMissing
    """

    pass


class OcspFetchFailure(Error):
    """
    OcspFetchFailure
    """

    pass


class FetchFailure(Error):
    """
    FetchFailure
    """


class OcspInvalidResponseStatus(Error):
    """
    OcspInvalidResponseStatus
    """

    pass


class OcspIssuerFetchFailure(Error):
    """
    OcspIssuerFetchFailure
    """

    pass


class LoadError(Error):
    """
    Risen when a IoCryptoParser implementing class could not be
    loaded properly.
    """


class RevokeCheckFailed(Error):
    """
    RevokeCheckFailed
    """

    pass


class CertIssuerMissingInChain(Error):
    """
    CertIssuerMissingInChain
    """

    pass


class NotCompleteChain(Error):
    """
    NotCompleteChain
    """

    pass


class CertExpired(Error):
    """
    CertExpired
    """

    pass


class SignatureVerificationFailed(Error):
    """
    SignatureVerificationFailed
    """

    pass


class InvalidSignedType(Error):
    """
    InvalidSignedType
    """

    pass


class MissingInit(Error):
    """
    Risen when the
    [InitCryptoParser][pki_tools.types.crypto_parser.InitCryptoParser]
    has not been initialized.
    """

    pass


class MissingBlockSize(Error):
    """
    MissingBlockSize
    """

    pass


class CrlIdpInvalid(Error):
    """
    CrlIdpInvalid
    """

    pass
