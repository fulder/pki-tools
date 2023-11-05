import abc
from typing import Type

from pydantic import BaseModel


class CryptoParser(BaseModel):
    __metaclass__ = abc.ABCMeta

    @classmethod
    @abc.abstractmethod
    def from_cryptography(
        cls: Type["CryptoParser"], crypto_obj
    ) -> "CryptoParser":
        """
        Parses a cryptography x509 object into a CryptoParser

        Arguments:
             crypto_obj --The cryptography object
        """
