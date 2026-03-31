import base64
import binascii
import quopri
from html import unescape
from urllib.parse import unquote

from .morse import decode_morse


def decode_base64(text: str) -> str:
    try:
        return base64.b64decode(text.encode("utf-8"), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        raise ValueError("Invalid Base64 format provided")


def decode_hex(text: str) -> str:
    try:
        return binascii.unhexlify(text.encode("utf-8")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        raise ValueError("Invalid Hex format provided")


def decode_binary(text: str) -> str:
    bits = text.strip().split()
    try:
        return bytes(int(chunk, 2) for chunk in bits).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        raise ValueError("Invalid Binary format provided")


def decode_url(text: str) -> str:
    return unquote(text)


def decode_base32(text: str) -> str:
    try:
        return base64.b32decode(text.encode("utf-8"), casefold=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        raise ValueError("Invalid Base32 format provided")


def decode_base85(text: str) -> str:
    try:
        return base64.a85decode(text.encode("utf-8")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        raise ValueError("Invalid Base85 format provided")


def decode_quoted_printable(text: str) -> str:
    try:
        return quopri.decodestring(text.encode("utf-8")).decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Invalid Quoted-printable format provided")


def decode_html_entities(text: str) -> str:
    return unescape(text)


def decode_uu(text: str) -> str:
    if not text.strip():
        return ""
    data = bytearray()
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            data.extend(binascii.a2b_uu(line.encode("ascii")))
        except (binascii.Error, ValueError, UnicodeEncodeError):
            raise ValueError("Invalid Uuencoding format provided")
    try:
        return bytes(data).decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Invalid Uuencoding format provided")


def decode_base64url(text: str) -> str:
    try:
        padding = "=" * ((4 - len(text) % 4) % 4)
        return base64.urlsafe_b64decode((text + padding).encode("utf-8")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        raise ValueError("Invalid Base64URL format provided")


def decode_base58(text: str) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = 0
    for ch in text:
        if ch not in alphabet:
            raise ValueError("Invalid Base58 format provided")
        num = num * 58 + alphabet.index(ch)
    # handle leading ones
    pad = 0
    for ch in text:
        if ch == "1":
            pad += 1
        else:
            break
    data = num.to_bytes((num.bit_length() + 7) // 8, "big") if num > 0 else b""
    return (b"\x00" * pad + data).decode("utf-8")


def decode_decimal(text: str) -> str:
    parts = text.strip().split()
    try:
        values = [int(p) for p in parts]
        if any(v < 0 or v > 255 for v in values):
            raise ValueError
        return bytes(values).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        raise ValueError("Invalid Decimal format provided")


def decode_octal(text: str) -> str:
    parts = text.strip().split()
    try:
        values = [int(p, 8) for p in parts]
        if any(v < 0 or v > 255 for v in values):
            raise ValueError
        return bytes(values).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        raise ValueError("Invalid Octal format provided")


def decode_caesar(text: str, shift: int) -> str:
    return encode_caesar(text, -shift)


def decode_rot13(text: str) -> str:
    return encode_caesar(text, 13)


def decode_morse_code(text: str) -> str:
    return decode_morse(text)


def decode_vigenere(text: str, key: str) -> str:
    if not key or not key.isalpha():
        raise ValueError("Vigenere key must be alphabetic")
    key = key.lower()
    result = []
    key_index = 0
    for ch in text:
        if ch.isalpha():
            shift = ord(key[key_index % len(key)]) - 97
            if "a" <= ch <= "z":
                result.append(chr(((ord(ch) - 97 - shift) % 26) + 97))
            else:
                result.append(chr(((ord(ch) - 65 - shift) % 26) + 65))
            key_index += 1
        else:
            result.append(ch)
    return "".join(result)


def decode_xor(text: str, key: str) -> str:
    if not key:
        raise ValueError("XOR key is required")
    try:
        data = binascii.unhexlify(text.encode("utf-8"))
    except (binascii.Error, ValueError):
        raise ValueError("Invalid XOR hex format provided")
    key_bytes = key.encode("utf-8")
    out = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Invalid XOR output for UTF-8")


def decode_atbash(text: str) -> str:
    result = []
    for ch in text:
        if "a" <= ch <= "z":
            result.append(chr(122 - (ord(ch) - 97)))
        elif "A" <= ch <= "Z":
            result.append(chr(90 - (ord(ch) - 65)))
        else:
            result.append(ch)
    return "".join(result)


def decode_baconian(text: str) -> str:
    tokens = text.strip().split()
    result = []
    for token in tokens:
        if token == "/":
            result.append(" ")
            continue
        if len(token) != 5 or any(ch not in "ABab" for ch in token):
            raise ValueError("Invalid Baconian format provided")
        value = 0
        for ch in token.upper():
            value = (value << 1) | (1 if ch == "B" else 0)
        if value < 0 or value > 25:
            raise ValueError("Invalid Baconian format provided")
        result.append(chr(65 + value))
    return "".join(result)


def decode_leet_speak(text: str) -> str:
    mapping = {
        "0": "O",
        "1": "I",
        "3": "E",
        "4": "A",
        "5": "S",
        "7": "T",
    }
    return "".join(mapping.get(ch, ch) for ch in text)


def decode_reverse(text: str) -> str:
    return text[::-1]


def decode_brainfuck(code: str) -> str:
    valid = set("+-<>[],.")
    if any(ch not in valid for ch in code):
        raise ValueError("Invalid Brainfuck format provided")

    tape = [0]
    ptr = 0
    output = []
    # Precompute bracket pairs
    stack = []
    pairs = {}
    for i, ch in enumerate(code):
        if ch == "[":
            stack.append(i)
        elif ch == "]":
            if not stack:
                raise ValueError("Invalid Brainfuck format provided")
            j = stack.pop()
            pairs[i] = j
            pairs[j] = i
    if stack:
        raise ValueError("Invalid Brainfuck format provided")

    i = 0
    while i < len(code):
        ch = code[i]
        if ch == "+":
            tape[ptr] = (tape[ptr] + 1) % 256
        elif ch == "-":
            tape[ptr] = (tape[ptr] - 1) % 256
        elif ch == ">":
            ptr += 1
            if ptr == len(tape):
                tape.append(0)
        elif ch == "<":
            ptr -= 1
            if ptr < 0:
                raise ValueError("Invalid Brainfuck format provided")
        elif ch == ".":
            output.append(chr(tape[ptr]))
        elif ch == ",":
            # no input stream; treat as zero
            tape[ptr] = 0
        elif ch == "[":
            if tape[ptr] == 0:
                i = pairs[i]
        elif ch == "]":
            if tape[ptr] != 0:
                i = pairs[i]
        i += 1

    return "".join(output)


def decode_rail_fence(text: str, rails: int) -> str:
    if rails < 2:
        raise ValueError("Rails must be >= 2")
    length = len(text)
    # Determine rail pattern
    pattern = []
    rail = 0
    direction = 1
    for _ in range(length):
        pattern.append(rail)
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
    # Count characters per rail
    counts = [pattern.count(r) for r in range(rails)]
    rails_data = []
    idx = 0
    for count in counts:
        rails_data.append(list(text[idx:idx + count]))
        idx += count
    # Reconstruct
    result = []
    rail_positions = [0] * rails
    for r in pattern:
        result.append(rails_data[r][rail_positions[r]])
        rail_positions[r] += 1
    return "".join(result)


def decode_polybius(text: str) -> str:
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    tokens = text.strip().split()
    result = []
    for token in tokens:
        if token == "/":
            result.append(" ")
            continue
        if len(token) != 2 or not token.isdigit():
            raise ValueError("Invalid Polybius format provided")
        row = int(token[0]) - 1
        col = int(token[1]) - 1
        if row not in range(5) or col not in range(5):
            raise ValueError("Invalid Polybius format provided")
        result.append(alphabet[row * 5 + col])
    return "".join(result)


def decode_unicode_escaped(text: str) -> str:
    if len(text) % 6 != 0:
        raise ValueError("Invalid Unicode escaped format provided")
    result = []
    i = 0
    while i < len(text):
        chunk = text[i:i + 6]
        if not chunk.startswith("\\u"):
            raise ValueError("Invalid Unicode escaped format provided")
        hex_part = chunk[2:]
        try:
            result.append(chr(int(hex_part, 16)))
        except ValueError:
            raise ValueError("Invalid Unicode escaped format provided")
        i += 6
    return "".join(result)


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
