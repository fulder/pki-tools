from typing import Dict


from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import \
    CertificatePublicKeyTypes
from pydantic import ConfigDict

from pki_tools.types.crypto_parser import CryptoParser


class SubjectPublicKeyInfo(CryptoParser):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    algorithm: str
    parameters: Dict[str, str]

    @classmethod
    def from_cryptography(cls, cert_public_key: CertificatePublicKeyTypes):
        name = str(cert_public_key.__class__).split(".")[-2].upper()
        parameters = {}
        if isinstance(cert_public_key, dsa.DSAPublicKey):
            pub_numbers = cert_public_key.public_numbers()
            param_numbers = pub_numbers.parameter_numbers
            parameters = {
                "key_size": str(cert_public_key.key_size),
                "public_key_y": pub_numbers.y,
                "prime_p": param_numbers.p,
                "subprime_q": param_numbers.q,
                "generator_g": param_numbers.g,
            }
        elif isinstance(cert_public_key, rsa.RSAPublicKey):
            pub_numbers = cert_public_key.public_numbers()
            parameters = {
                "key_size": str(cert_public_key.key_size),
                "modulus_n": str(pub_numbers.n),
                "exponent_e": str(pub_numbers.e),
            }
        elif isinstance(cert_public_key, ec.EllipticCurvePublicKey):
            pub_numbers = cert_public_key.public_numbers()
            parameters = {
                "key_size": str(cert_public_key.key_size),
                "x_coordinate": str(pub_numbers.x),
                "y_coordinate": str(pub_numbers.y),
                "curve": pub_numbers.curve.name,
            }

        return cls(algorithm=name, parameters=parameters)

    def _string_dict(self):
        params = {}
        for k, v in self.parameters.items():
            key = " ".join(ele.title() for ele in k.split("_"))
            params[key] = v

        return {"Public Key Algorithm": self.algorithm, "Parameters": params}
