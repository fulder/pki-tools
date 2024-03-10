class Error(Exception):
    pass


class ExtensionMissing(Error):
    pass


class OcspFetchFailure(Error):
    pass


class FetchFailure(Error):
    """
    FetchFailure
    """


class OcspInvalidResponseStatus(Error):
    pass


class OcspIssuerFetchFailure(Error):
    pass


class CrlFetchFailure(Error):
    pass


class CrlLoadError(Error):
    """
    Thrown when CRL could not be loaded due to e.g. invalid format
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


class InvalidKeyType(Error):
    """
    MissingBlockSize
    """

    pass
