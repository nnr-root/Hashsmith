import base64
import binascii
import quopri
from html import escape
from urllib.parse import quote

from .morse import encode_morse


def encode_base64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("utf-8")


def encode_hex(text: str) -> str:
    return binascii.hexlify(text.encode("utf-8")).decode("utf-8")


def encode_binary(text: str) -> str:
    return " ".join(format(byte, "08b") for byte in text.encode("utf-8"))


def encode_url(text: str) -> str:
    return quote(text, safe="")


def encode_base32(text: str) -> str:
    return base64.b32encode(text.encode("utf-8")).decode("utf-8")


def encode_base85(text: str) -> str:
    return base64.a85encode(text.encode("utf-8")).decode("utf-8")


def encode_quoted_printable(text: str) -> str:
    return quopri.encodestring(text.encode("utf-8")).decode("ascii")


def encode_html_entities(text: str) -> str:
    return escape(text, quote=True)


def encode_uu(text: str) -> str:
    data = text.encode("utf-8")
    if not data:
        return ""
    lines = []
    for i in range(0, len(data), 45):
        chunk = data[i:i + 45]
        lines.append(binascii.b2a_uu(chunk).decode("ascii").rstrip("\n"))
    return "\n".join(lines)


def encode_base64url(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("utf-8").rstrip("=")


def encode_base58(text: str) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    data = text.encode("utf-8")
    num = int.from_bytes(data, "big")
    enc = []
    while num > 0:
        num, rem = divmod(num, 58)
        enc.append(alphabet[rem])
    # handle leading zeros
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + "".join(reversed(enc or [alphabet[0]]))


def encode_decimal(text: str) -> str:
    return " ".join(str(byte) for byte in text.encode("utf-8"))


def encode_octal(text: str) -> str:
    return " ".join(format(byte, "o") for byte in text.encode("utf-8"))


def encode_brainfuck(text: str) -> str:
    # Simple encoder: adjust current cell with +/- and output with .
    current = 0
    output = []
    for ch in text:
        target = ord(ch)
        delta = target - current
        if delta > 0:
            output.append("+" * delta)
        elif delta < 0:
            output.append("-" * (-delta))
        output.append(".")
        current = target
    return "".join(output)


def encode_rail_fence(text: str, rails: int) -> str:
    if rails < 2:
        raise ValueError("Rails must be >= 2")
    fence = ["" for _ in range(rails)]
    rail = 0
    direction = 1
    for ch in text:
        fence[rail] += ch
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
    return "".join(fence)


def encode_polybius(text: str) -> str:
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # I/J combined
    pairs = []
    for ch in text.upper():
        if ch == "J":
            ch = "I"
        if ch in alphabet:
            idx = alphabet.index(ch)
            row = idx // 5 + 1
            col = idx % 5 + 1
            pairs.append(f"{row}{col}")
        elif ch == " ":
            pairs.append("/")
    return " ".join(pairs)


def encode_unicode_escaped(text: str) -> str:
    return "".join(f"\\u{ord(ch):04x}" for ch in text)


def encode_caesar(text: str, shift: int) -> str:
    shift = shift % 26
    result = []
    for ch in text:
        if "a" <= ch <= "z":
            result.append(chr(((ord(ch) - 97 + shift) % 26) + 97))
        elif "A" <= ch <= "Z":
            result.append(chr(((ord(ch) - 65 + shift) % 26) + 65))
        else:
            result.append(ch)
    return "".join(result)


def encode_rot13(text: str) -> str:
    return encode_caesar(text, 13)


def encode_morse_code(text: str) -> str:
    return encode_morse(text)


def encode_vigenere(text: str, key: str) -> str:
    if not key or not key.isalpha():
        raise ValueError("Vigenere key must be alphabetic")
    key = key.lower()
    result = []
    key_index = 0
    for ch in text:
        if ch.isalpha():
            shift = ord(key[key_index % len(key)]) - 97
            if "a" <= ch <= "z":
                result.append(chr(((ord(ch) - 97 + shift) % 26) + 97))
            else:
                result.append(chr(((ord(ch) - 65 + shift) % 26) + 65))
            key_index += 1
        else:
            result.append(ch)
    return "".join(result)


def encode_xor(text: str, key: str) -> str:
    if not key:
        raise ValueError("XOR key is required")
    data = text.encode("utf-8")
    key_bytes = key.encode("utf-8")
    out = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
    return binascii.hexlify(out).decode("utf-8")


def encode_atbash(text: str) -> str:
    result = []
    for ch in text:
        if "a" <= ch <= "z":
            result.append(chr(122 - (ord(ch) - 97)))
        elif "A" <= ch <= "Z":
            result.append(chr(90 - (ord(ch) - 65)))
        else:
            result.append(ch)
    return "".join(result)


def encode_baconian(text: str) -> str:
    tokens = []
    for ch in text:
        if ch == " ":
            tokens.append("/")
            continue
        if ch.isalpha():
            idx = ord(ch.upper()) - 65
            if 0 <= idx < 26:
                code = "".join("B" if (idx >> bit) & 1 else "A" for bit in range(4, -1, -1))
                tokens.append(code)
    return " ".join(tokens)


def encode_leet_speak(text: str) -> str:
    mapping = {
        "A": "4",
        "E": "3",
        "S": "5",
        "T": "7",
        "O": "0",
    }
    result = []
    for ch in text:
        repl = mapping.get(ch.upper())
        result.append(repl if repl else ch)
    return "".join(result)


def encode_reverse(text: str) -> str:
    return text[::-1]
