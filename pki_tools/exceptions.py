class Error(Exception):
    pass


class ExtensionMissing(Error):
    pass


class CertLoadError(Error):
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
    pass


class CsrLoadError(Error):
    pass


class RevokeCheckFailed(Error):
    pass


class CertIssuerMissingInChain(Error):
    pass


class NotCompleteChain(Error):
    pass


class CertExpired(Error):
    pass


class SignatureVerificationFailed(Error):
    pass


class InvalidSignedType(Error):
    pass


class MissingInit(Error):
    pass


class MissingBlockSize(Error):
    pass


class InvalidKeyType(Error):
    pass
