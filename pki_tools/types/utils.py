import binascii

from cryptography.hazmat.bindings._rust import ObjectIdentifier


def oid_to_name(oid: str):
    return ObjectIdentifier(oid)._name

def _byte_to_hex(bytes_in: bytes) -> str:
    return binascii.hexlify(bytes_in).decode().upper()


def _hex_to_byte(hex_string: str) -> bytes:
    byte_array = bytearray()
    for i in range(0, len(hex_string), 2):
        byte_array.append(int(hex_string[i:i+2], 16))

    return bytes(byte_array)
