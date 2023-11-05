import binascii


def _byte_to_hex(bytes_in: bytes):
    return binascii.hexlify(bytes_in).decode().upper()