
from typing import Type

from cryptography.x509 import ocsp

from pki_tools.types.crypto_parser import CryptoParser
from pki_tools.types.name import Name


class OCSPResponse(CryptoParser):


    @classmethod
    def from_cryptography(
            cls: Type["OCSPResponse"],
            crypto_ocsp_response: ocsp.OCSPResponse
    ) -> "OCSPResponse":
