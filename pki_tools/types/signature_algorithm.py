from typing import Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from pydantic import BaseModel, ConfigDict


class SignatureAlgorithm(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    algorithm: hashes.HashAlgorithm
    parameters: Union[None, padding.PSS, padding.PKCS1v15, ec.ECDSA] = None

    def _string_dict(self):
        ret = {
            "algorithm": self.algorithm.name,
        }

        if self.parameters is not None:
            ret["parameters"] = self.parameters.name

        return ret
