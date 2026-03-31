import base64
import binascii
import re
import string
from typing import List, Tuple

from ..algorithms.decoding import (
    decode_base58,
    decode_hex,
    decode_binary,
    decode_decimal,
    decode_octal,
    decode_base64,
    decode_base32,
    decode_base85,
    decode_quoted_printable,
    decode_html_entities,
    decode_uu,
    decode_base64url,
    decode_morse_code,
    decode_baconian,
    decode_polybius,
    decode_unicode_escaped,
    decode_url,
    decode_rot13,
    decode_atbash,
    decode_caesar,
    decode_leet_speak,
    decode_reverse,
    decode_brainfuck,
    decode_rail_fence,
    decode_vigenere,
    decode_xor,
)
from ..algorithms.encoding import (
    encode_base58,
    encode_hex,
    encode_binary,
    encode_decimal,
    encode_octal,
    encode_base64,
    encode_base32,
    encode_base85,
    encode_quoted_printable,
    encode_html_entities,
    encode_uu,
    encode_base64url,
    encode_morse_code,
    encode_baconian,
    encode_polybius,
    encode_unicode_escaped,
    encode_url,
    encode_caesar,
)
from ..algorithms.morse import REVERSE_MORSE


COMMON_BIGRAMS = (
    "th",
    "he",
    "in",
    "er",
    "an",
    "re",
    "nd",
    "on",
    "en",
    "at",
    "ou",
    "ed",
    "ha",
    "to",
    "or",
    "it",
    "is",
    "hi",
    "es",
    "ng",
    "st",
    "ar",
    "te",
    "se",
    "me",
    "ve",
    "of",
)

COMMON_WORDS = (
    "the",
    "and",
    "you",
    "that",
    "have",
    "for",
    "not",
    "with",
    "this",
    "but",
    "from",
    "hello",
    "secret",
    "message",
    "attack",
    "dawn",
)


def _normalize_spaces(value: str) -> str:
    return " ".join(value.strip().split())


def _is_hex(value: str) -> bool:
    return bool(value) and all(ch in "0123456789abcdefABCDEF" for ch in value)


def _vowel_ratio(value: str) -> float:
    letters = [ch.lower() for ch in value if ch.isalpha()]
    if not letters:
        return 0.0
    vowels = sum(1 for ch in letters if ch in "aeiou")
    return vowels / len(letters)


def _alpha_count(value: str) -> int:
    return sum(1 for ch in value if ch.isalpha())


def _alpha_ratio(value: str) -> float:
    if not value:
        return 0.0
    return _alpha_count(value) / len(value)


def _printable_ratio(value: bytes) -> float:
    if not value:
        return 0.0
    printable = sum(1 for ch in value if chr(ch) in string.printable)
    return printable / len(value)


def _alnum_space_ratio(value: bytes) -> float:
    if not value:
        return 0.0
    allowed = set(string.ascii_letters + string.digits + " ")
    count = sum(1 for ch in value if chr(ch) in allowed)
    return count / len(value)


def _bigram_score(value: str) -> float:
    text = re.sub(r"[^a-z]", "", value.lower())
    if len(text) < 2:
        return 0.0
    count = 0
    for i in range(len(text) - 1):
        if text[i : i + 2] in COMMON_BIGRAMS:
            count += 1
    return count / max(len(text) - 1, 1)


def _word_hit(value: str) -> bool:
    text = re.sub(r"[^a-z ]", " ", value.lower())
    tokens = [token for token in text.split() if token]
    hits = [word for word in COMMON_WORDS if word in tokens]
    if any(len(word) >= 4 for word in hits):
        return True
    return len(hits) >= 2


def _text_score(value: str) -> float:
    return _bigram_score(value) + (0.6 if _word_hit(value) else 0.0) + (_vowel_ratio(value) * 0.4)


def _index_of_coincidence(value: str) -> float:
    letters = [ch.lower() for ch in value if ch.isalpha()]
    n = len(letters)
    if n < 2:
        return 0.0
    counts = {}
    for ch in letters:
        counts[ch] = counts.get(ch, 0) + 1
    numerator = sum(count * (count - 1) for count in counts.values())
    return numerator / (n * (n - 1))


def _best_shift_score(value: str) -> Tuple[int, float, float]:
    original_score = _bigram_score(value)
    best_shift = 0
    best_score = 0.0
    for shift in range(1, 26):
        decoded = decode_caesar(value, shift)
        score = _bigram_score(decoded)
        if score > best_score:
            best_score = score
            best_shift = shift
    return best_shift, original_score, best_score


def _best_shift_vowel_ratio(value: str) -> Tuple[int, float, float]:
    original_ratio = _vowel_ratio(value)
    best_shift = 0
    best_ratio = 0.0
    for shift in range(1, 26):
        decoded = decode_caesar(value, shift)
        ratio = _vowel_ratio(decoded)
        if ratio > best_ratio:
            best_ratio = ratio
            best_shift = shift
    return best_shift, original_ratio, best_ratio


def _try_single_byte_xor(hex_text: str) -> Tuple[float, float]:
    try:
        raw = binascii.unhexlify(hex_text)
    except (binascii.Error, ValueError):
        return 0.0, 0.0
    raw_printable = _printable_ratio(raw)
    best_printable = 0.0
    best_score = 0.0
    for key in range(256):
        decoded = bytes(b ^ key for b in raw)
        printable_ratio = _printable_ratio(decoded)
        if printable_ratio > best_printable:
            best_printable = printable_ratio
        if printable_ratio >= 0.9:
            text = decoded.decode("utf-8", errors="ignore")
            best_score = max(best_score, _bigram_score(text))
    return raw_printable, best_score


def detect_encoding_types(text: str) -> List[str]:
    value = text.strip()
    if not value:
        return []

    if value.startswith(("$2a$", "$2b$", "$2y$", "$argon2", "scrypt$")):
        return []
    if value.startswith("*") and len(value) == 41:
        return []
    if value.startswith("md5") and len(value) == 35:
        return []
    if value.lower().startswith("0x0100"):
        return []

    strong_results: List[str] = []
    heuristic_results: List[str] = []

    # Binary (8-bit groups)
    normalized = _normalize_spaces(value)
    if re.fullmatch(r"[01]{8}( [01]{8})*", normalized):
        try:
            decoded = decode_binary(normalized)
            if _normalize_spaces(encode_binary(decoded)) == normalized:
                strong_results.append("binary")
        except Exception:
            pass

    # Decimal (space-separated 0-255)
    if re.fullmatch(r"\d{1,3}( \d{1,3})*", normalized):
        try:
            decoded = decode_decimal(normalized)
            if _normalize_spaces(encode_decimal(decoded)) == normalized:
                strong_results.append("decimal")
        except Exception:
            pass

    # Octal (space-separated 0-7)
    if re.fullmatch(r"[0-7]{1,3}( [0-7]{1,3})*", normalized):
        try:
            decoded = decode_octal(normalized)
            if _normalize_spaces(encode_octal(decoded)) == normalized:
                strong_results.append("octal")
        except Exception:
            pass

    # Polybius (1-5 pairs and / for spaces)
    if re.fullmatch(r"[1-5/ ]+", normalized):
        try:
            decoded = decode_polybius(normalized)
            if _normalize_spaces(encode_polybius(decoded)) == normalized:
                strong_results.append("polybius")
        except Exception:
            pass

    # Baconian (A/B tokens)
    if re.fullmatch(r"[ABab/ ]+", normalized):
        try:
            decoded = decode_baconian(normalized)
            if _normalize_spaces(encode_baconian(decoded).upper()) == normalized.upper():
                strong_results.append("baconian")
        except Exception:
            pass

    # Morse (tokens must be known)
    if re.fullmatch(r"[.\-/ ]+", normalized):
        tokens = normalized.split()
        if tokens and all(token in REVERSE_MORSE for token in tokens):
            try:
                decoded = decode_morse_code(normalized)
                if _normalize_spaces(encode_morse_code(decoded)) == normalized:
                    strong_results.append("morse")
            except Exception:
                pass

    # Unicode escaped (\uXXXX)
    if re.fullmatch(r"(?:\\u[0-9a-fA-F]{4})+", value):
        try:
            decoded = decode_unicode_escaped(value)
            if encode_unicode_escaped(decoded) == value.lower():
                strong_results.append("unicode")
        except Exception:
            pass

    # Hex (strict, UTF-8 round-trip)
    hex_bytes = None
    hex_printable = 0.0
    hex_text_score = 0.0
    has_hex_alpha = False
    if len(value) % 2 == 0 and _is_hex(value):
        try:
            decoded = decode_hex(value)
            if encode_hex(decoded).lower() == value.lower():
                strong_results.append("hex")
            hex_bytes = binascii.unhexlify(value)
            hex_printable = _printable_ratio(hex_bytes)
            hex_text_score = _bigram_score(hex_bytes.decode("utf-8", errors="ignore"))
            has_hex_alpha = any(ch in "abcdef" for ch in value.lower())
            hex_alnum_space = _alnum_space_ratio(hex_bytes)
        except Exception:
            pass

    if _is_hex(value) and not strong_results and len(value) >= 16:
        return []

    # Base64 (strict, padded)
    try:
        decoded = decode_base64(value)
        if encode_base64(decoded) == value:
            strong_results.append("base64")
    except Exception:
        pass

    # Base64URL (unpadded, URL-safe)
    if "=" not in value and re.fullmatch(r"[A-Za-z0-9_-]+", value):
        try:
            decoded = decode_base64url(value)
            if encode_base64url(decoded) == value:
                strong_results.append("base64url")
        except Exception:
            pass

    # Base32 (strict, padded)
    try:
        decoded = decode_base32(value)
        if encode_base32(decoded) == value.upper():
            strong_results.append("base32")
    except Exception:
        pass

    # Base85 (strict round-trip)
    try:
        decoded = decode_base85(value)
        if encode_base85(decoded) == value:
            strong_results.append("base85")
    except Exception:
        pass

    # Quoted-printable
    if "=" in value:
        try:
            decoded = decode_quoted_printable(value)
            if encode_quoted_printable(decoded) == value:
                strong_results.append("quoted-printable")
        except Exception:
            pass

    # HTML entities
    if "&" in value and ";" in value:
        try:
            decoded = decode_html_entities(value)
            if encode_html_entities(decoded) == value:
                strong_results.append("html-entities")
        except Exception:
            pass

    # Uuencoding
    if all(32 <= ord(ch) <= 126 or ch in "\r\n\t" for ch in value):
        try:
            decoded = decode_uu(value)
            if decoded and encode_uu(decoded) == value:
                strong_results.append("uu")
        except Exception:
            pass

    # Base58 (strict round-trip)
    try:
        decoded = decode_base58(value)
        if encode_base58(decoded) == value:
            strong_results.append("base58")
    except Exception:
        pass

    # URL encoding (must include at least one valid %XX)
    if re.search(r"%[0-9A-Fa-f]{2}", value):
        try:
            decoded = decode_url(value)
            if encode_url(decoded) == value:
                strong_results.append("url")
        except Exception:
            pass
    # Brainfuck
    if re.fullmatch(r"[+\-<>\[\].,]+", value):
        try:
            decoded = decode_brainfuck(value)
            if decoded:
                strong_results.append("brainf*ck")
        except Exception:
            pass

    # Prefer polybius when present to avoid overlap with decimal/octal
    if "polybius" in strong_results:
        return ["polybius"]

    # If any strong format matched, return only those
    if strong_results:
        if "hex" in strong_results and hex_bytes is not None:
            raw_printable, xor_score = _try_single_byte_xor(value)
            raw_text_score = _bigram_score(hex_bytes.decode("utf-8", errors="ignore"))
            decoded_text = hex_bytes.decode("utf-8", errors="ignore")
            if hex_printable >= 0.9 and (
                _word_hit(decoded_text)
                or (_alpha_ratio(decoded_text) >= 0.6 and _vowel_ratio(decoded_text) >= 0.25)
                or raw_text_score >= 0.1
            ):
                return ["hex"]
            if (
                (has_hex_alpha or hex_alnum_space < 0.85)
                and (
                    (raw_printable < 0.6 and xor_score - raw_text_score >= 0.05)
                    or (raw_text_score < 0.01 and xor_score - raw_text_score >= 0.1)
                )
            ):
                return ["xor"]
        return list(dict.fromkeys(strong_results))

    # ROT13 short-word check (avoid false positives by requiring word hit)
    if re.fullmatch(r"[A-Za-z ]+", value) and 4 <= len(value.strip()) < 6:
        rot13_decoded = decode_rot13(value)
        if _word_hit(rot13_decoded) and not _word_hit(value):
            return ["rot13"]

    # ROT13 / Caesar / Atbash / Reverse / Rail fence heuristics
    if re.fullmatch(r"[A-Za-z ]+", value) and len(value.strip()) >= 6:
        base_score = _text_score(value)
        base_word_hit = _word_hit(value)
        base_vowel = _vowel_ratio(value)
        base_alpha = _alpha_ratio(value)
        candidate_scores: dict[str, float] = {}
        candidate_texts: dict[str, str] = {}

        rot13_decoded = decode_rot13(value)
        candidate_scores["rot13"] = _text_score(rot13_decoded)
        candidate_texts["rot13"] = rot13_decoded

        best_shift = 0
        best_caesar_score = 0.0
        second_caesar_score = 0.0
        best_caesar_text = value
        for shift in range(1, 26):
            if shift == 13:
                continue
            decoded = decode_caesar(value, shift)
            score = _text_score(decoded)
            if score > best_caesar_score:
                second_caesar_score = best_caesar_score
                best_caesar_score = score
                best_shift = shift
                best_caesar_text = decoded
            elif score > second_caesar_score:
                second_caesar_score = score
        if best_shift:
            candidate_scores["caesar"] = best_caesar_score
            candidate_texts["caesar"] = best_caesar_text

        atbash_decoded = decode_atbash(value)
        candidate_scores["atbash"] = _text_score(atbash_decoded)
        candidate_texts["atbash"] = atbash_decoded

        reverse_decoded = decode_reverse(value)
        candidate_scores["reverse"] = _text_score(reverse_decoded)
        candidate_texts["reverse"] = reverse_decoded

        best_rf_score = 0.0
        best_rf_text = ""
        for rails in range(2, 6):
            try:
                decoded = decode_rail_fence(value, rails)
            except Exception:
                continue
            score = _text_score(decoded)
            if score > best_rf_score:
                best_rf_score = score
                best_rf_text = decoded
        if best_rf_text and (_word_hit(best_rf_text) or _bigram_score(best_rf_text) >= 0.2):
            candidate_scores["railfence"] = best_rf_score
            candidate_texts["railfence"] = best_rf_text

        best_match, best_score = max(candidate_scores.items(), key=lambda item: item[1])
        ic_value = _index_of_coincidence(value)
        best_text = candidate_texts.get(best_match, "")
        any_word_hit = any(_word_hit(text) for text in candidate_texts.values())
        score_delta = best_score - base_score
        allow_heuristics = (
            (not base_word_hit and base_score < 0.18)
            or (score_delta >= 0.15 and best_score >= 0.25)
        )

        if allow_heuristics:
            if best_match == "caesar" and score_delta >= 0.05 and len(value.strip()) > 12:
                heuristic_results.append("caesar")
            elif best_match in {"caesar", "rot13", "atbash"} and not any_word_hit and len(value.strip()) <= 12:
                if not base_word_hit and base_score < 0.18:
                    heuristic_results.append("vigenere")
            elif best_match == "caesar" and (best_score - base_score) >= 0.12:
                heuristic_results.append("caesar")
            elif (
                best_match in {"caesar", "rot13", "atbash"}
                and not any_word_hit
                and score_delta < 0.05
                and len(value.strip()) >= 8
                and not base_word_hit
                and base_score < 0.18
            ):
                heuristic_results.append("vigenere")
            elif (
                best_match == "caesar"
                and not any_word_hit
                and (best_caesar_score - second_caesar_score) < 0.15
                and len(value.strip()) >= 8
                and not base_word_hit
                and base_score < 0.18
            ):
                heuristic_results.append("vigenere")
            elif (
                ic_value < 0.06
                and not any_word_hit
                and score_delta < 0.05
                and len(value.strip()) >= 8
                and not base_word_hit
                and base_score < 0.18
            ):
                heuristic_results.append("vigenere")
            elif (
                best_match in {"caesar", "rot13", "atbash"}
                and not _word_hit(best_text)
                and ic_value < 0.06
                and best_score < 0.35
                and len(value.strip()) >= 8
                and not base_word_hit
                and base_score < 0.18
            ):
                heuristic_results.append("vigenere")
            elif (
                ic_value < 0.055
                and (best_score - base_score) < 0.08
                and len(value.strip()) >= 8
                and not base_word_hit
                and base_score < 0.18
            ):
                heuristic_results.append("vigenere")
            elif best_match == "reverse":
                reverse_bigram = _bigram_score(best_text)
                if (
                    _word_hit(best_text)
                    or (
                        reverse_bigram >= 0.25
                        and _vowel_ratio(best_text) >= 0.3
                        and base_score <= 0.1
                        and (best_score - base_score) >= 0.12
                    )
                ):
                    heuristic_results.append("reverse")
            elif best_score >= max(0.2, base_score + 0.08):
                if not (base_alpha >= 0.85 and base_vowel >= 0.28 and base_score >= 0.18):
                    heuristic_results.append(best_match)

    # Leet (heuristic, require mixed letters+digits)
    if not _is_hex(value) and any(ch.isalpha() for ch in value) and any(ch in "013457" for ch in value):
        decoded = decode_leet_speak(value)
        original_score = _bigram_score(value)
        decoded_score = _bigram_score(decoded)
        if _word_hit(decoded) or (decoded_score >= 0.12 and original_score <= 0.05):
            heuristic_results.append("leet")

    # XOR (single-byte key heuristic on hex)
    if len(value) % 2 == 0 and _is_hex(value):
        if hex_bytes is not None:
            raw_printable, xor_score = _try_single_byte_xor(value)
            raw_text_score = _bigram_score(hex_bytes.decode("utf-8", errors="ignore"))
            if (
                (has_hex_alpha or hex_alnum_space < 0.85)
                and (
                    (raw_printable < 0.6 and xor_score - raw_text_score >= 0.05)
                    or (raw_text_score < 0.01 and xor_score - raw_text_score >= 0.1)
                )
            ):
                heuristic_results.append("xor")

    return list(dict.fromkeys(heuristic_results))


def _weights_for_hex_length(length: int) -> List[Tuple[str, float]]:
    return {
        16: [("mysql323", 1.0)],
        32: [("md5", 0.7), ("ntlm", 0.2), ("md4", 0.1)],
        40: [("sha1", 0.7), ("ripemd160", 0.2), ("mssql2000", 0.1)],
        56: [("sha224", 0.8), ("sha3_224", 0.2)],
        64: [("sha256", 0.7), ("sha3_256", 0.2), ("blake2s", 0.1)],
        96: [("sha384", 1.0)],
        128: [("sha512", 0.7), ("sha3_512", 0.2), ("blake2b", 0.1)],
    }.get(length, [])


def _normalize_percentages(items: List[Tuple[str, float]]) -> List[Tuple[str, int]]:
    if not items:
        return []
    total = sum(weight for _, weight in items) or 1.0
    raw = [(name, weight / total * 100.0) for name, weight in items]
    rounded = [(name, int(round(pct))) for name, pct in raw]
    diff = 100 - sum(pct for _, pct in rounded)
    if diff != 0:
        name, pct = rounded[0]
        rounded[0] = (name, pct + diff)
    return rounded


def detect_hash_probabilities(value: str, top: int = 3) -> List[Tuple[str, int]]:
    text = value.strip()
    if not text:
        return []

    if text.startswith(("$2a$", "$2b$", "$2y$")):
        return [("bcrypt", 100)]
    if text.startswith("$argon2"):
        return [("argon2", 100)]
    if text.startswith("scrypt$"):
        return [("scrypt", 100)]
    if text.lower().startswith("0x0100"):
        return _normalize_percentages([("mssql2005", 0.5), ("mssql2012", 0.5)])
    if text.startswith("md5") and len(text) == 35:
        return [("postgres", 100)]
    if text.startswith("*") and len(text) == 41:
        return [("mysql41", 100)]

    if not _is_hex(text):
        return []

    weights = _weights_for_hex_length(len(text))
    if not weights:
        return []

    weights = sorted(weights, key=lambda item: item[1], reverse=True)[:top]
    return _normalize_percentages(weights)
