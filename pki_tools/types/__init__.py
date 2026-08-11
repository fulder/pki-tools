import yaml

from .certificate import Certificate, Validity
from .certificates import Certificates
from .chain import Chain
from .crl import CertificateRevocationList
from .csr import CertificateSigningRequest
from .enums import RevokeMode
from .extensions import Extensions
from .key_pair import (
    CryptoKeyPair,
    CryptoPrivateKey,
    CryptoPublicKey,
    DSAKeyPair,
    DSAPrivateKey,
    DSAPublicKey,
    Ed448KeyPair,
    Ed448PrivateKey,
    Ed448PublicKey,
    Ed25519KeyPair,
    Ed25519PrivateKey,
    Ed25519PublicKey,
    EllipticCurveKeyPair,
    EllipticCurveName,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    RSAKeyPair,
    RSAPrivateKey,
    RSAPublicKey,
)
from .name import Name
from .ocsp import (
    OcspCertificateStatus,
    OCSPRequest,
    OCSPResponse,
    OcspResponseStatus,
)
from .signature_algorithm import (
    MD5,
    SHA1,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHA512_224,
    SHA512_256,
    SHAKE128,
    SHAKE256,
    SM3,
    BLAKE2b,
    BLAKE2s,
    HashAlgorithm,
    HashAlgorithmName,
    SignatureAlgorithm,
)

MAX_YAML_LEN = 80


def str_presenter(dumper, data):
    if len(data) > MAX_YAML_LEN:
        chunks = [
            data[i : i + MAX_YAML_LEN]
            for i in range(0, len(data), MAX_YAML_LEN)
        ]

        data = "\n".join(chunks)
        return dumper.represent_scalar(
            "tag:yaml.org,2002:str", data, style="|"
        )
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


yaml.representer.SafeRepresenter.add_representer(str, str_presenter)
