class Error(Exception):
    pass


class ExtensionMissing(Error):
    pass


class Revoked(Error):
    pass


class CertLoadError(Error):
    pass
