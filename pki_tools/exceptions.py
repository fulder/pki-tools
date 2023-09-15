class Error(Exception):
    pass


class ExtensionMissing(Error):
    pass


class CertLoadError(Error):
    pass


class OcspFetchFailure(Error):
    pass


class CrlFetchFailure(Error):
    pass


class CrlLoadError(Error):
    pass
