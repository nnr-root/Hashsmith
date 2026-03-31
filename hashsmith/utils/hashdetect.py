from typing import List


def detect_hash_types(hash_value: str) -> List[str]:
    value = hash_value.strip()
    if value.startswith(("$2a$", "$2b$", "$2y$")):
        return ["bcrypt"]
    if value.startswith("$argon2"):
        return ["argon2"]
    if value.startswith("scrypt$"):
        return ["scrypt"]
    if value.lower().startswith("0x0100"):
        return ["mssql2005", "mssql2012"]
    if value.startswith("md5") and len(value) == 35:
        return ["postgres"]
    if value.startswith("*") and len(value) == 41:
        return ["mysql41"]

    hex_value = value.lower()
    is_hex = all(ch in "0123456789abcdef" for ch in hex_value)
    if not is_hex:
        return []

    length_map = {
        16: ["mysql323"],
        32: ["md5", "md4", "ntlm"],
        40: ["sha1", "ripemd160", "mssql2000"],
        56: ["sha224", "sha3_224"],
        64: ["sha256", "sha3_256", "blake2s"],
        96: ["sha384"],
        128: ["sha512", "sha3_512", "blake2b"],
    }
    return length_map.get(len(hex_value), [])
