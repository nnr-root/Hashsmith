import hashlib
import os
from typing import Callable, Dict, Optional, Tuple

try:
    import bcrypt  # type: ignore
except Exception:  # pragma: no cover
    bcrypt = None


HASH_FUNCS: Dict[str, Callable[[bytes], "hashlib._Hash"]] = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha3_224": hashlib.sha3_224,
    "sha3_256": hashlib.sha3_256,
    "sha3_512": hashlib.sha3_512,
    "blake2b": hashlib.blake2b,
    "blake2s": hashlib.blake2s,
}


def _md4(message: bytes) -> bytes:
    # Minimal MD4 implementation
    def f(x, y, z):
        return (x & y) | (~x & z)

    def g(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def h(x, y, z):
        return x ^ y ^ z

    def left_rotate(x, n):
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    msg = message
    orig_len_bits = (8 * len(msg)) & 0xFFFFFFFFFFFFFFFF
    msg += b"\x80"
    while (len(msg) % 64) != 56:
        msg += b"\x00"
    msg += orig_len_bits.to_bytes(8, "little")

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for offset in range(0, len(msg), 64):
        X = [int.from_bytes(msg[offset + i:offset + i + 4], "little") for i in range(0, 64, 4)]
        aa, bb, cc, dd = a, b, c, d

        # Round 1
        s = [3, 7, 11, 19]
        for i in range(16):
            k = i
            r = i % 4
            a = left_rotate((a + f(b, c, d) + X[k]) & 0xFFFFFFFF, s[r])
            a, b, c, d = d, a, b, c

        # Round 2
        s = [3, 5, 9, 13]
        for i in range(16):
            k = (i % 4) * 4 + (i // 4)
            r = i % 4
            a = left_rotate((a + g(b, c, d) + X[k] + 0x5A827999) & 0xFFFFFFFF, s[r])
            a, b, c, d = d, a, b, c

        # Round 3
        s = [3, 9, 11, 15]
        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(16):
            k = order[i]
            r = i % 4
            a = left_rotate((a + h(b, c, d) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s[r])
            a, b, c, d = d, a, b, c

        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    return b"".join(x.to_bytes(4, "little") for x in (a, b, c, d))


def _mysql323(text: str) -> str:
    nr = 1345345333
    add = 7
    nr2 = 0x12345671
    for ch in text:
        if ch in (" ", "\t"):
            continue
        tmp = ord(ch)
        nr ^= (((nr & 63) + add) * tmp) + (nr << 8)
        nr &= 0xFFFFFFFF
        nr2 += (nr2 << 8) ^ nr
        nr2 &= 0xFFFFFFFF
        add += tmp
    return f"{nr & 0x7FFFFFFF:08x}{nr2 & 0x7FFFFFFF:08x}"


def _mysql41(text: str) -> str:
    stage1 = hashlib.sha1(text.encode("utf-8")).digest()
    stage2 = hashlib.sha1(stage1).hexdigest().upper()
    return "*" + stage2


def _ntlm(text: str) -> str:
    return _md4(text.encode("utf-16le")).hex()


def _mssql2000(text: str) -> str:
    return hashlib.sha1(text.encode("utf-16le")).hexdigest().upper()


def _mssql2005_hash(text: str, salt: bytes) -> str:
    return hashlib.sha1(salt + text.encode("utf-16le")).hexdigest().upper()


def _parse_salt_bytes(salt: str, default_len: int = 16) -> bytes:
    if not salt:
        return os.urandom(default_len)
    salt_value = salt.strip()
    if salt_value.startswith("0x"):
        salt_value = salt_value[2:]
    if salt_value and all(ch in "0123456789abcdefABCDEF" for ch in salt_value) and len(salt_value) % 2 == 0:
        return bytes.fromhex(salt_value)
    return salt_value.encode("utf-8")


def _argon2_hash(text: str, salt: str) -> str:
    try:
        from argon2.low_level import Type, hash_secret  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise ValueError("argon2-cffi library is required for argon2 hashing") from exc

    salt_bytes = _parse_salt_bytes(salt, default_len=16)
    return hash_secret(
        text.encode("utf-8"),
        salt_bytes,
        time_cost=2,
        memory_cost=102400,
        parallelism=8,
        hash_len=32,
        type=Type.ID,
    ).decode("utf-8")


def _scrypt_hash(text: str, salt: str) -> str:
    salt_bytes = _parse_salt_bytes(salt, default_len=16)
    n = 2**14
    r = 8
    p = 1
    dklen = 64
    digest = hashlib.scrypt(text.encode("utf-8"), salt=salt_bytes, n=n, r=r, p=p, dklen=dklen)
    return f"scrypt${n}${r}${p}${salt_bytes.hex()}${digest.hex()}"


def _postgres_md5(text: str, username: str) -> str:
    if not username:
        raise ValueError("postgres requires a username as salt (use --salt)")
    digest = hashlib.md5(f"{text}{username}".encode("utf-8")).hexdigest()
    return f"md5{digest}"


def hash_text(text: str, algorithm: str, salt: str = "", salt_mode: str = "prefix") -> str:
    algo = algorithm.lower()
    if algo not in HASH_FUNCS and algo not in {
        "ripemd160",
        "md4",
        "ntlm",
        "mysql323",
        "mysql41",
        "bcrypt",
        "argon2",
        "scrypt",
        "mssql2000",
        "mssql2005",
        "mssql2012",
        "postgres",
    }:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    salt_in_algorithms = {"bcrypt", "argon2", "scrypt", "postgres", "mssql2000", "mssql2005", "mssql2012"}
    if salt and algo not in salt_in_algorithms:
        if salt_mode == "suffix":
            text = f"{text}{salt}"
        else:
            text = f"{salt}{text}"

    if algo == "md4":
        return _md4(text.encode("utf-8")).hex()
    if algo == "ntlm":
        return _ntlm(text)
    if algo == "mysql323":
        return _mysql323(text)
    if algo == "mysql41":
        return _mysql41(text)
    if algo == "mssql2000":
        return _mssql2000(text)
    if algo in {"mssql2005", "mssql2012"}:
        salt_bytes = _parse_salt_bytes(salt, default_len=4)
        digest = _mssql2005_hash(text, salt_bytes)
        return f"0x0100{salt_bytes.hex()}{digest}"
    if algo == "postgres":
        return _postgres_md5(text, salt)
    if algo == "argon2":
        return _argon2_hash(text, salt)
    if algo == "scrypt":
        return _scrypt_hash(text, salt)
    if algo == "bcrypt":
        if bcrypt is None:
            raise ValueError("bcrypt library is required for bcrypt hashing")
        if not salt:
            raise ValueError("bcrypt requires a salt (use --salt)")
        if salt.isdigit():
            salt_bytes = bcrypt.gensalt(rounds=int(salt))
        else:
            salt_bytes = salt.encode("utf-8")
        return bcrypt.hashpw(text.encode("utf-8"), salt_bytes).decode("utf-8")
    if algo == "ripemd160":
        try:
            h = hashlib.new("ripemd160")
        except ValueError as exc:
            raise ValueError("RIPEMD-160 is not available in this Python/OpenSSL build") from exc
        h.update(text.encode("utf-8"))
        return h.hexdigest()
    h = HASH_FUNCS[algo]()
    h.update(text.encode("utf-8"))
    return h.hexdigest()
