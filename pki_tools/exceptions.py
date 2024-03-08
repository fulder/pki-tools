class Error(Exception):
    pass


class ExtensionMissing(Error):
    pass


class CertLoadError(Error):
    """
    Thrown when the cert could not be loaded e.g. due to invalid PEM format
    """

    pass


class OcspFetchFailure(Error):
    pass


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


class CsrLoadError(Error):
    """
    CsrLoadError
    """

    pass


class RevokeCheckFailed(Error):
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
    pass


class InvalidKeyType(Error):
    pass
