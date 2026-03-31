import argparse
import os
import time
from typing import Optional

from rich.console import Console
from rich.prompt import IntPrompt, Prompt
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.text import Text

from .algorithms.cracking import brute_force, dictionary_attack, format_rate
from .algorithms.decoding import (
    decode_base64,
    decode_base32,
    decode_base85,
    decode_quoted_printable,
    decode_html_entities,
    decode_uu,
    decode_base64url,
    decode_base58,
    decode_binary,
    decode_caesar,
    decode_decimal,
    decode_hex,
    decode_octal,
    decode_morse_code,
    decode_rot13,
    decode_url,
    decode_vigenere,
    decode_xor,
    decode_atbash,
    decode_baconian,
    decode_leet_speak,
    decode_reverse,
    decode_brainfuck,
    decode_rail_fence,
    decode_polybius,
    decode_unicode_escaped,
)
from .algorithms.encoding import (
    encode_base64,
    encode_base32,
    encode_base85,
    encode_quoted_printable,
    encode_html_entities,
    encode_uu,
    encode_base64url,
    encode_base58,
    encode_binary,
    encode_caesar,
    encode_decimal,
    encode_hex,
    encode_octal,
    encode_morse_code,
    encode_rot13,
    encode_url,
    encode_vigenere,
    encode_xor,
    encode_atbash,
    encode_baconian,
    encode_leet_speak,
    encode_reverse,
    encode_brainfuck,
    encode_rail_fence,
    encode_polybius,
    encode_unicode_escaped,
)
from .algorithms.hashing import hash_text
from .utils.banner import render_banner
from .utils.clipboard import copy_to_clipboard
from .utils.identify import detect_encoding_types, detect_hash_probabilities
from .utils.io import read_text_from_file, resolve_input, write_text_to_file
from .utils.wordlist import iter_wordlist
from .utils.hashdetect import detect_hash_types
from pathlib import Path


THEMES = {
    "cyan": "cyan",
    "green": "green",
    "magenta": "magenta",
    "blue": "blue",
    "yellow": "yellow",
    "red": "red",
    "white": "white",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hashsmith",
        description="Hashsmith CLI for encoding, decoding, hashing, and cracking.",
        epilog=(
            "Examples:\n"
            "  hashsmith encode -t base64 -i \"hello\"\n"
            "  hashsmith identify -i \"aGVsbG8=\"\n"
            "  hashsmith -id -i \"aGVsbG8=\"\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-N", "--no-banner", action="store_true", help="Disable banner")
    parser.add_argument("-T", "--theme", choices=list(THEMES.keys()), default="cyan", help="Accent color")
    parser.add_argument("-A", "--help-all", action="store_true", help="Show help for all commands")
    parser.add_argument("-id", "--identify", action="store_true", help="Shortcut for identify command")

    main_input_group = parser.add_argument_group("Input Options")
    main_input_group.add_argument("-i", "--text", help="Text input")
    main_input_group.add_argument("-f", "--file", help="Read input from file")

    main_output_group = parser.add_argument_group("Output Options")
    main_output_group.add_argument("-o", "--out", help="Write output to file")
    main_output_group.add_argument("-c", "--copy", action="store_true", help="Copy output to clipboard")

    subparsers = parser.add_subparsers(dest="command")
    subparser_map: dict[str, argparse.ArgumentParser] = {}

    input_parent = argparse.ArgumentParser(add_help=False)
    input_group = input_parent.add_argument_group("Input Options")
    input_group.add_argument("-i", "--text", help="Text input")
    input_group.add_argument("-f", "--file", help="Read input from file")

    output_parent = argparse.ArgumentParser(add_help=False)
    output_group = output_parent.add_argument_group("Output Options")
    output_group.add_argument("-o", "--out", help="Write output to file")
    output_group.add_argument("-c", "--copy", action="store_true", help="Copy output to clipboard")

    encode_decode_parent = argparse.ArgumentParser(add_help=False)
    encode_decode_group = encode_decode_parent.add_argument_group("Algorithm Parameters")
    encode_decode_group.add_argument(
        "-t",
        "--type",
        required=True,
        choices=[
            "base64",
            "base64url",
            "base32",
            "base85",
            "quoted-printable",
            "html-entities",
            "uu",
            "base58",
            "hex",
            "binary",
            "decimal",
            "octal",
            "morse",
            "url",
            "caesar",
            "rot13",
            "vigenere",
            "xor",
            "atbash",
            "baconian",
            "leet",
            "reverse",
            "brainf*ck",
            "railfence",
            "polybius",
            "unicode",
        ],
    )
    encode_decode_group.add_argument("-s", "--shift", type=int, default=3, help="Shift for Caesar")
    encode_decode_group.add_argument("-k", "--key", help="Key for Vigenere/XOR")
    encode_decode_group.add_argument("-r", "--rails", type=int, default=2, help="Rails for Rail Fence")

    crack_input_parent = argparse.ArgumentParser(add_help=False)
    crack_input_group = crack_input_parent.add_argument_group("Input Options")
    crack_input_group.add_argument("-H", "--hash", required=True, dest="target_hash")
    crack_input_group.add_argument("-w", "--wordlist", help="Wordlist path for dictionary attack")

    identify_parser = subparsers.add_parser(
        "identify",
        help="Identify encoding and hash types",
        parents=[input_parent, output_parent],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  hashsmith identify -i \"aGVsbG8=\"\n"
            "  hashsmith identify -i 5f4dcc3b5aa765d61d8327deb882cf99\n"
            "  hashsmith identify -f data.txt -o report.txt\n"
        ),
    )
    subparser_map["identify"] = identify_parser

    encode_parser = subparsers.add_parser(
        "encode",
        help="Encode text",
        parents=[input_parent, output_parent, encode_decode_parent],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  hashsmith encode -t base64 -i \"hello\"\n"
            "  hashsmith encode -t caesar -s 5 -f input.txt -o output.txt\n"
            "  hashsmith encode -t hex -i \"hello\" -c\n"
        ),
    )
    subparser_map["encode"] = encode_parser

    decode_parser = subparsers.add_parser(
        "decode",
        help="Decode text",
        parents=[input_parent, output_parent, encode_decode_parent],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  hashsmith decode -t base64 -i \"aGVsbG8=\"\n"
            "  hashsmith decode -t base64 -f data.txt -o result.txt\n"
            "  hashsmith decode -t hex -i \"68656c6c6f\" -c\n"
        ),
    )
    subparser_map["decode"] = decode_parser

    hash_parser = subparsers.add_parser(
        "hash",
        help="Hash text",
        parents=[input_parent, output_parent],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  hashsmith hash -t sha256 -i \"admin\" -c\n"
            "  hashsmith hash -t md5 -i \"secret\" -s pepper -S suffix\n"
            "  hashsmith hash -t sha1 -f input.txt -o hashes.txt\n"
        ),
    )
    subparser_map["hash"] = hash_parser
    hash_params = hash_parser.add_argument_group("Algorithm Parameters")
    hash_output_format = hash_parser.add_argument_group("Output Format")

    hash_params.add_argument("-t", "--type", required=True, choices=[
        "md5", "md4", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_512",
        "blake2b", "blake2s", "ripemd160", "ntlm", "mysql323", "mysql41", "bcrypt",
        "argon2", "scrypt", "mssql2000", "mssql2005", "mssql2012", "postgres"
    ])
    hash_params.add_argument("-s", "--salt", default="", help="Salt value")
    hash_params.add_argument("-S", "--salt-mode", default="prefix", choices=["prefix", "suffix"])
    hash_output_format.add_argument("-e", "--out-encoding", default="hex", choices=["hex", "base58"], help="Output encoding for hex hashes")

    crack_parser = subparsers.add_parser(
        "crack",
        help="Crack hash",
        parents=[crack_input_parent, output_parent],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  hashsmith crack -t md5 -H 5f4dcc3b5aa765d61d8327deb882cf99 -M dict -w wordlists/common.txt\n"
            "  hashsmith crack -t sha1 -H 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed -M brute -n 1 -x 4\n"
            "  hashsmith crack -t md5 -H 5f4dcc3b5aa765d61d8327deb882cf99 -M dict -w wordlists/common.txt -c\n"
        ),
    )
    subparser_map["crack"] = crack_parser
    crack_params = crack_parser.add_argument_group("Algorithm Parameters")

    crack_params.add_argument("-t", "--type", required=True, choices=[
        "auto", "md5", "md4", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_512",
        "blake2b", "blake2s", "ripemd160", "ntlm", "mysql323", "mysql41", "bcrypt",
        "argon2", "scrypt", "mssql2000", "mssql2005", "mssql2012", "postgres"
    ])
    crack_params.add_argument("-M", "--mode", required=True, choices=["dict", "brute"])
    crack_params.add_argument("-C", "--charset", default="abcdefghijklmnopqrstuvwxyz0123456789")
    crack_params.add_argument("-n", "--min-len", type=int, default=1)
    crack_params.add_argument("-x", "--max-len", type=int, default=4)
    crack_params.add_argument("-s", "--salt", default="")
    crack_params.add_argument("-S", "--salt-mode", default="prefix", choices=["prefix", "suffix"])
    crack_params.add_argument("-p", "--workers", type=int, default=0, help="Parallel workers for cracking (0=auto)")

    interactive_parser = subparsers.add_parser(
        "interactive",
        help="Guided interactive mode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  hashsmith interactive\n"
        ),
    )
    subparser_map["interactive"] = interactive_parser

    parser.set_defaults(_subparser_map=subparser_map)

    return parser


def handle_encode(args: argparse.Namespace, console: Console) -> str:
    text = resolve_input(args.text, args.file)
    if args.type in {"vigenere", "xor"} and not args.key:
        raise ValueError("This algorithm requires --key")
    if args.type == "railfence" and args.rails < 2:
        raise ValueError("Rails must be >= 2")
    if args.type == "base64":
        return encode_base64(text)
    if args.type == "base64url":
        return encode_base64url(text)
    if args.type == "base32":
        return encode_base32(text)
    if args.type == "base85":
        return encode_base85(text)
    if args.type == "quoted-printable":
        return encode_quoted_printable(text)
    if args.type == "html-entities":
        return encode_html_entities(text)
    if args.type == "uu":
        return encode_uu(text)
    if args.type == "base58":
        return encode_base58(text)
    if args.type == "hex":
        return encode_hex(text)
    if args.type == "binary":
        return encode_binary(text)
    if args.type == "decimal":
        return encode_decimal(text)
    if args.type == "octal":
        return encode_octal(text)
    if args.type == "morse":
        return encode_morse_code(text)
    if args.type == "url":
        return encode_url(text)
    if args.type == "caesar":
        return encode_caesar(text, args.shift)
    if args.type == "rot13":
        return encode_rot13(text)
    if args.type == "vigenere":
        return encode_vigenere(text, args.key)
    if args.type == "xor":
        return encode_xor(text, args.key)
    if args.type == "atbash":
        return encode_atbash(text)
    if args.type == "baconian":
        return encode_baconian(text)
    if args.type == "leet":
        return encode_leet_speak(text)
    if args.type == "reverse":
        return encode_reverse(text)
    if args.type == "brainf*ck":
           return encode_brainfuck(text)
    if args.type == "railfence":
        return encode_rail_fence(text, args.rails)
    if args.type == "polybius":
        return encode_polybius(text)
    if args.type == "unicode":
        return encode_unicode_escaped(text)
    raise ValueError("Unsupported encode type")


def handle_decode(args: argparse.Namespace, console: Console) -> str:
    text = resolve_input(args.text, args.file)
    if args.type in {"vigenere", "xor"} and not args.key:
        raise ValueError("This algorithm requires --key")
    if args.type == "railfence" and args.rails < 2:
        raise ValueError("Rails must be >= 2")
    if args.type == "base64":
        return decode_base64(text)
    if args.type == "base64url":
        return decode_base64url(text)
    if args.type == "base32":
        return decode_base32(text)
    if args.type == "base85":
        return decode_base85(text)
    if args.type == "quoted-printable":
        return decode_quoted_printable(text)
    if args.type == "html-entities":
        return decode_html_entities(text)
    if args.type == "uu":
        return decode_uu(text)
    if args.type == "base58":
        return decode_base58(text)
    if args.type == "hex":
        return decode_hex(text)
    if args.type == "binary":
        return decode_binary(text)
    if args.type == "decimal":
        return decode_decimal(text)
    if args.type == "octal":
        return decode_octal(text)
    if args.type == "morse":
        return decode_morse_code(text)
    if args.type == "url":
        return decode_url(text)
    if args.type == "caesar":
        return decode_caesar(text, args.shift)
    if args.type == "rot13":
        return decode_rot13(text)
    if args.type == "vigenere":
        return decode_vigenere(text, args.key)
    if args.type == "xor":
        return decode_xor(text, args.key)
    if args.type == "atbash":
        return decode_atbash(text)
    if args.type == "baconian":
        return decode_baconian(text)
    if args.type == "leet":
        return decode_leet_speak(text)
    if args.type == "reverse":
        return decode_reverse(text)
    if args.type == "brainf*ck":
           return decode_brainfuck(text)
    if args.type == "railfence":
        return decode_rail_fence(text, args.rails)
    if args.type == "polybius":
        return decode_polybius(text)
    if args.type == "unicode":
        return decode_unicode_escaped(text)
    raise ValueError("Unsupported decode type")


def handle_hash(args: argparse.Namespace, console: Console) -> str:
    text = resolve_input(args.text, args.file)
    result = hash_text(text, args.type, args.salt, args.salt_mode)
    out_encoding = getattr(args, "out_encoding", "hex")
    if out_encoding == "base58":
        hex_value = result[2:] if result.startswith("0x") else result
        if not is_hex_string(hex_value):
            raise ValueError("Base58 output is only supported for hex hashes")
        result = encode_base58_bytes(bytes.fromhex(hex_value))
    return result


def handle_identify(args: argparse.Namespace, console: Console) -> str:
    text = resolve_input(args.text, args.file)
    encodings = detect_encoding_types(text)
    hash_probs = detect_hash_probabilities(text, top=3)

    if encodings and not (encodings == ["hex"] and hash_probs):
        return "\n".join(f"{item} encoded text" for item in encodings)

    if hash_probs:
        return "\n".join(f"{pct}% {name}" for name, pct in hash_probs)

    return "Probably raw text"


def is_hex_string(value: str) -> bool:
    if not value:
        return False
    value = value.strip()
    return all(ch in "0123456789abcdefABCDEF" for ch in value)


def encode_base58_bytes(data: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    if not data:
        return alphabet[0]
    num = int.from_bytes(data, "big")
    enc = []
    while num > 0:
        num, rem = divmod(num, 58)
        enc.append(alphabet[rem])
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + "".join(reversed(enc))


def count_wordlist_entries(path: str) -> Optional[int]:
    try:
        count = 0
        with Path(path).expanduser().resolve().open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                if line.strip():
                    count += 1
        return count
    except Exception:
        return None


def handle_crack(args: argparse.Namespace, console: Console, accent: str = "cyan") -> int:
    def build_progress() -> Progress:
        accent_color = accent or "cyan"
        return Progress(
            SpinnerColumn(),
            TextColumn(f"[bold {accent_color}]{{task.description}}"),
            BarColumn(bar_width=None, style=accent_color, complete_style=accent_color),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TextColumn(f"[bold {accent_color}]•"),
            TimeRemainingColumn(),
            TextColumn(f"[bold {accent_color}]•"),
            TextColumn(f"[bold {accent_color}]{{task.fields[speed]}} H/s"),
            console=console,
        )

    if args.mode == "dict":
        if args.workers < 1:
            args.workers = os.cpu_count() or 1
        if args.type == "bcrypt" and args.workers > 1:
            console.print("[yellow]bcrypt is CPU-expensive; multi-processing may not scale well.[/yellow]")
        if not args.wordlist:
            console.print("[red]--wordlist is required for dict mode[/red]")
            return 2
        total = count_wordlist_entries(args.wordlist)
        progress = build_progress()
        task_id = progress.add_task("Cracking", total=total, speed="0")

        attempts = 0
        last_render = 0
        update_every = 1000
        start = time.perf_counter()

        def progress_callback(delta: int) -> None:
            nonlocal attempts, last_render
            attempts += delta
            if attempts - last_render < update_every:
                return
            elapsed = max(time.perf_counter() - start, 1e-6)
            speed = f"{attempts / elapsed:,.2f}"
            progress.update(task_id, advance=attempts - last_render, speed=speed)
            last_render = attempts

        try:
            with progress:
                try:
                    result = dictionary_attack(
                        args.target_hash,
                        args.type,
                        iter_wordlist(args.wordlist),
                        args.salt,
                        args.salt_mode,
                        workers=args.workers,
                        progress_callback=progress_callback,
                    )
                finally:
                    elapsed = max(time.perf_counter() - start, 1e-6)
                    speed = f"{attempts / elapsed:,.2f}"
                    if total is not None:
                        progress.update(task_id, completed=total, speed=speed)
                    else:
                        progress.update(task_id, advance=max(attempts - last_render, 0), speed=speed)
                    progress.refresh()
        except KeyboardInterrupt:
            progress.stop()
            raise
    else:
        if args.workers < 1:
            args.workers = os.cpu_count() or 1
        if args.type == "bcrypt" and args.workers > 1:
            console.print("[yellow]bcrypt is CPU-expensive; multi-processing may not scale well.[/yellow]")
        total = 0
        charset_len = len(args.charset)
        for length in range(args.min_len, args.max_len + 1):
            total += charset_len ** length
        progress = build_progress()
        task_id = progress.add_task("Cracking", total=total, speed="0")

        attempts = 0
        last_render = 0
        update_every = 1000
        start = time.perf_counter()

        def progress_callback(delta: int) -> None:
            nonlocal attempts, last_render
            attempts += delta
            if attempts - last_render < update_every:
                return
            elapsed = max(time.perf_counter() - start, 1e-6)
            speed = f"{attempts / elapsed:,.2f}"
            progress.update(task_id, advance=attempts - last_render, speed=speed)
            last_render = attempts

        try:
            with progress:
                try:
                    result = brute_force(
                        args.target_hash,
                        args.type,
                        charset=args.charset,
                        min_len=args.min_len,
                        max_len=args.max_len,
                        salt=args.salt,
                        salt_mode=args.salt_mode,
                        workers=args.workers,
                        progress_callback=progress_callback,
                    )
                finally:
                    elapsed = max(time.perf_counter() - start, 1e-6)
                    speed = f"{attempts / elapsed:,.2f}"
                    progress.update(task_id, completed=total, speed=speed)
                    progress.refresh()
        except KeyboardInterrupt:
            progress.stop()
            raise

    if result.found:
        console.print(f"[green]Found:[/green] {result.password}")
        if getattr(args, "copy", False):
            if copy_to_clipboard(result.password or ""):
                console.print("[green]Copied to clipboard[/green]")
            else:
                console.print("[yellow]Unable to copy to clipboard[/yellow]")
        if getattr(args, "out", None):
            write_text_to_file(args.out, result.password or "")
            console.print(f"[green]Saved to {args.out}[/green]")
    else:
        console.print("[yellow]Not found[/yellow]")

    console.print(
        Text(
            f"Attempts: {result.attempts} | Elapsed: {result.elapsed:.2f}s | Rate: {format_rate(result.rate)}",
            style=accent,
        )
    )
    return 0


def output_result(result: str, out: Optional[str], console: Console, copy: bool = False) -> None:
    if out:
        write_text_to_file(out, result)
        console.print(f"[green]Saved to {out}[/green]")
    else:
        console.file.write(f"{result}\n")
        console.file.flush()
    if copy:
        if copy_to_clipboard(result):
            console.print("[green]Copied to clipboard[/green]")
        else:
            console.print("[yellow]Unable to copy to clipboard[/yellow]")


def output_identify_result(
    result: str,
    out: Optional[str],
    console: Console,
    copy: bool,
    accent: str,
) -> None:
    if out:
        write_text_to_file(out, result)
        console.print(f"[green]Saved to {out}[/green]")
    else:
        console.print(Text(result, style=accent))
    if copy:
        if copy_to_clipboard(result):
            console.print("[green]Copied to clipboard[/green]")
        else:
            console.print("[yellow]Unable to copy to clipboard[/yellow]")


def interactive_mode(console: Console, accent: str) -> None:
    console.print(f"[bold {accent}]Interactive mode[/bold {accent}]")

    class BackAction(Exception):
        pass

    def maybe_exit(value: str) -> None:
        if value.strip().lower() in {"bye", "exit", "q", "quit"}:
            console.print(f"[bold {accent}]Goodbye[/bold {accent}]")
            raise SystemExit(0)

    def ask_text(label: str, default: Optional[str] = None) -> str:
        value = Prompt.ask(label, default=default)
        maybe_exit(value)
        return value

    def ask_int(label: str, default: int) -> int:
        attempts = 0
        while attempts < 3:
            value = Prompt.ask(label, default=str(default))
            maybe_exit(value)
            try:
                return int(value)
            except ValueError:
                attempts += 1
                console.print("[red]Invalid number.[/red] Please try again.")
        console.print("[red]Too many invalid attempts. Exiting.[/red]")
        raise SystemExit(2)

    def choose_option(label: str, options: list[str], default_index: int = 1) -> str:
        attempts = 0
        while attempts < 3:
            console.print(f"\n{label}:")
            def format_option(key: str, text: str) -> str:
                spacer = "  " if len(key) == 1 else " "
                return f"  [{accent}]{key}[/{accent}]){spacer}{text}"

            console.print(format_option("0", "Back"))
            key_map: dict[str, str] = {}
            numeric_index = 1
            for option in options:
                if option == "identify":
                    key_map["i"] = option
                    console.print(format_option("i", option))
                    continue
                key = str(numeric_index)
                key_map[key] = option
                console.print(format_option(key, option))
                numeric_index += 1
            console.print(format_option("q", "Quit"))
            default_hint = f"[{accent}]\\[{default_index}][/{accent}]"
            raw = console.input(f"Select option {default_hint}: ").strip().lower()
            if raw == "":
                raw = str(default_index)
            if raw == "0":
                raise BackAction()
            if raw in key_map:
                return key_map[raw]
            maybe_exit(raw)
            try:
                choice = int(raw)
            except ValueError:
                attempts += 1
                console.print("[red]Invalid selection.[/red] Please try again.")
                continue
            selected = key_map.get(str(choice))
            if selected:
                return selected
            attempts += 1
            console.print("[red]Invalid selection.[/red] Please try again.")
        console.print("[red]Too many invalid attempts. Exiting.[/red]")
        raise SystemExit(2)

    def ask_yes_no(label: str, default: bool = False) -> bool:
        attempts = 0
        default_str = "y" if default else "n"
        hint = "Y/n" if default else "y/N"
        hint_markup = f"[{accent}]\\[{hint}][/{accent}]"
        while attempts < 3:
            value = console.input(f"{label} {hint_markup}: ")
            if value.strip() == "":
                value = default_str
            maybe_exit(value)
            normalized = value.strip().lower()
            if normalized in {"y", "yes"}:
                return True
            if normalized in {"n", "no"}:
                return False
            attempts += 1
            console.print("[red]Invalid input.[/red] Use yes/no.")
        console.print("[red]Too many invalid attempts. Exiting.[/red]")
        raise SystemExit(2)

    # Helper: get input either text or file (reusable)
    def _get_interactive_input(prompt_label: str) -> tuple[Optional[str], Optional[str]]:
        while True:
            choice = choose_option(prompt_label, ["enter custom text", "use file"], default_index=1)
            if choice == "enter custom text":
                txt = ask_text("Enter text", default="Hashsmith_Sample")
                return txt, None
            if choice == "use file":
                fp = ask_text("File path")
                try:
                    content = read_text_from_file(fp)
                except ValueError as exc:
                    console.print(f"[bold red]Error:[/bold red] {exc}")
                    continue
                return content, None

    def _get_interactive_output() -> tuple[Optional[str], bool]:
        copy_output = ask_yes_no("Copy output to clipboard?", default=True)
        if ask_yes_no("Save output to file?", default=False):
            out_choice = choose_option("Output path", ["use default output.txt", "enter custom path"], default_index=1)
            out_path = "output.txt" if out_choice.startswith("use default") else ask_text("Output file path")
            return out_path, copy_output
        return None, copy_output

    actions = ["encode", "decode", "hash", "crack", "set-theme", "identify"]
    while True:
        try:
            action = choose_option("Choose action", actions, default_index=1)

            if action == "set-theme":
                theme_keys = list(THEMES.keys())
                selected = choose_option("Select theme", theme_keys, default_index=1)
                accent = THEMES.get(selected, "cyan")
                render_banner(console, accent)
                console.print(f"Theme set to [bold {accent}]{selected}[/bold {accent}]")
                continue

            if action in {"encode", "decode", "hash"}:
                out_path, copy_output = _get_interactive_output()

                if action == "encode":
                    enc_options = [
                        "base64", "base64url", "base32", "base85", "quoted-printable", "html-entities", "uu", "base58", "hex", "binary", "decimal", "octal",
                        "morse", "url", "caesar", "rot13", "vigenere", "xor", "atbash",
                        "baconian", "leet", "reverse", "brainf*ck", "railfence", "polybius", "unicode",
                    ]
                    enc_type = choose_option("Encoding type", enc_options, default_index=1)
                    shift = ask_int("Caesar shift", default=3) if enc_type == "caesar" else 3
                    text, file_path = _get_interactive_input("Input source")
                    key = None
                    rails = 2
                    if enc_type in {"vigenere", "xor"}:
                        key = ask_text("Key")
                    if enc_type == "railfence":
                        rails = ask_int("Rails", default=2)
                    args = argparse.Namespace(type=enc_type, text=text or None, file=file_path, shift=shift, key=key, rails=rails)
                    try:
                        result = handle_encode(args, console)
                        output_result(result, out_path, console, copy=copy_output)
                        return
                    except ValueError as exc:
                        console.print(f"[bold red]Error:[/bold red] {exc}")
                        continue

                if action == "decode":
                    dec_options = [
                        "base64", "base64url", "base32", "base85", "quoted-printable", "html-entities", "uu", "base58", "hex", "binary", "decimal", "octal",
                        "morse", "url", "caesar", "rot13", "vigenere", "xor", "atbash",
                        "baconian", "leet", "reverse", "brainf*ck", "railfence", "polybius", "unicode",
                    ]
                    dec_type = choose_option("Decoding type", dec_options, default_index=1)
                    shift = ask_int("Caesar shift", default=3) if dec_type == "caesar" else 3
                    text, file_path = _get_interactive_input("Input source")
                    key = None
                    rails = 2
                    if dec_type in {"vigenere", "xor"}:
                        key = ask_text("Key")
                    if dec_type == "railfence":
                        rails = ask_int("Rails", default=2)
                    args = argparse.Namespace(type=dec_type, text=text or None, file=file_path, shift=shift, key=key, rails=rails)
                    try:
                        result = handle_decode(args, console)
                        output_result(result, out_path, console, copy=copy_output)
                        return
                    except ValueError as exc:
                        console.print(f"[bold red]Error:[/bold red] {exc}")
                        continue

                hash_options = [
                    "md5", "md4", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_512",
                    "blake2b", "blake2s", "ripemd160", "ntlm", "mysql323", "mysql41", "bcrypt",
                    "argon2", "scrypt", "mssql2000", "mssql2005", "mssql2012", "postgres",
                ]
                hash_type = choose_option("Hash type", hash_options, default_index=3)
                text, file_path = _get_interactive_input("Input source")
                salt = ""
                if hash_type == "bcrypt":
                    salt = ask_text("Salt (or rounds)", default="12")
                elif hash_type == "postgres":
                    salt = ask_text("Username (salt)")
                elif ask_yes_no("Use salt?", default=False):
                    salt = ask_text("Salt value")
                salt_mode = choose_option("Salt mode", ["prefix", "suffix"], default_index=1) if salt else "prefix"
                out_encoding = choose_option("Output encoding", ["hex", "base58"], default_index=1)
                args = argparse.Namespace(
                    type=hash_type,
                    text=text or None,
                    file=file_path,
                    salt=salt,
                    salt_mode=salt_mode,
                    out_encoding=out_encoding,
                )
                try:
                    result = handle_hash(args, console)
                    output_result(result, out_path, console, copy=copy_output)
                    return
                except ValueError as exc:
                    console.print(f"[bold red]Error:[/bold red] {exc}")
                    continue

            if action == "identify":
                text = ask_text("Enter text")
                args = argparse.Namespace(text=text, file=None)
                try:
                    result = handle_identify(args, console)
                    console.print(Text(result, style=accent))
                    return
                except ValueError as exc:
                    console.print(f"[bold red]Error:[/bold red] {exc}")
                    continue

            crack_type = choose_option(
                "Hash type",
                [
                    "auto", "md5", "md4", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_512",
                    "blake2b", "blake2s", "ripemd160", "ntlm", "mysql323", "mysql41", "bcrypt",
                    "argon2", "scrypt", "mssql2000", "mssql2005", "mssql2012", "postgres",
                ],
                default_index=1,
            )
            mode = choose_option("Mode", ["dict", "brute"], default_index=1)
            while True:
                target_hash = ask_text("Target hash")
                if crack_type != "auto" and crack_type not in {"bcrypt", "argon2", "scrypt", "postgres"} and not is_hex_string(target_hash) and not target_hash.startswith("*") and not target_hash.lower().startswith("0x0100"):
                    console.print("[bold red]Error:[/bold red] Hash must be hexadecimal (0-9, a-f).")
                    continue
                break
            if crack_type == "auto":
                candidates = detect_hash_types(target_hash)
                if not candidates:
                    console.print("[bold red]Error:[/bold red] Unable to detect hash type.")
                    continue
                if len(candidates) == 1:
                    crack_type = candidates[0]
                else:
                    crack_type = choose_option("Detected types", candidates, default_index=1)
            salt = ""
            if ask_yes_no("Use salt?", default=False):
                salt = ask_text("Salt value")
            salt_mode = choose_option("Salt mode", ["prefix", "suffix"], default_index=1) if salt else "prefix"

            if mode == "dict":
                wordlist_choice = choose_option("Wordlist", ["use default wordlists/common.txt", "enter custom path"], default_index=1)
                wordlist = "wordlists/common.txt" if wordlist_choice.startswith("use default") else ask_text("Wordlist path")
                workers = ask_int("Workers", default=os.cpu_count() or 1)
                copy_output = ask_yes_no("Copy cracked password to clipboard?", default=True)
                args = argparse.Namespace(
                    type=crack_type,
                    target_hash=target_hash,
                    mode=mode,
                    wordlist=wordlist,
                    charset="",
                    min_len=1,
                    max_len=4,
                    salt=salt,
                    salt_mode=salt_mode,
                    workers=workers,
                    copy=copy_output,
                )
                raise SystemExit(handle_crack(args, console, accent))

            charset_choice = choose_option("Charset", ["use default [a-z0-9]", "enter custom"], default_index=1)
            charset = "abcdefghijklmnopqrstuvwxyz0123456789" if charset_choice.startswith("use default") else ask_text("Charset")
            min_len = ask_int("Min length", default=1)
            max_len = ask_int("Max length", default=4)
            copy_output = ask_yes_no("Copy cracked password to clipboard?", default=True)
            args = argparse.Namespace(
                type=crack_type,
                target_hash=target_hash,
                mode=mode,
                wordlist=None,
                charset=charset,
                min_len=min_len,
                max_len=max_len,
                salt=salt,
                salt_mode=salt_mode,
                workers=1,
                copy=copy_output,
            )
            raise SystemExit(handle_crack(args, console, accent))
        except BackAction:
            continue


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    console = Console()

    accent = THEMES.get(args.theme, "cyan")

    if getattr(args, "help_all", False):
        parser.print_help()
        subparser_map = getattr(args, "_subparser_map", {})
        for name, subparser in subparser_map.items():
            print(f"\n{name} command help:\n")
            subparser.print_help()
        raise SystemExit(0)

    try:
        if args.identify:
            if args.command and args.command != "identify":
                console.print("[bold red]Error:[/bold red] -id cannot be combined with another command.")
                raise SystemExit(2)
            if not args.no_banner:
                render_banner(console, accent)
            try:
                result = handle_identify(args, console)
                output_identify_result(result, args.out, console, copy=args.copy, accent=accent)
            except ValueError as exc:
                console.print(f"[bold red]Error:[/bold red] {exc}")
                raise SystemExit(2)
        elif args.command is None:
            if not args.no_banner:
                render_banner(console, accent)
            interactive_mode(console, accent)
        elif args.command == "interactive":
            if not args.no_banner:
                render_banner(console, accent)
            interactive_mode(console, accent)
        elif args.command == "encode":
            if not args.no_banner:
                render_banner(console, accent)
            try:
                result = handle_encode(args, console)
                output_result(result, args.out, console, copy=args.copy)
            except ValueError as exc:
                console.print(f"[bold red]Error:[/bold red] {exc}")
                raise SystemExit(2)
        elif args.command == "decode":
            if not args.no_banner:
                render_banner(console, accent)
            try:
                result = handle_decode(args, console)
                output_result(result, args.out, console, copy=args.copy)
            except ValueError as exc:
                console.print(f"[bold red]Error:[/bold red] {exc}")
                raise SystemExit(2)
        elif args.command == "hash":
            if not args.no_banner:
                render_banner(console, accent)
            try:
                result = handle_hash(args, console)
                output_result(result, args.out, console, copy=args.copy)
            except ValueError as exc:
                console.print(f"[bold red]Error:[/bold red] {exc}")
                raise SystemExit(2)
        elif args.command == "identify":
            if not args.no_banner:
                render_banner(console, accent)
            try:
                result = handle_identify(args, console)
                output_identify_result(result, args.out, console, copy=args.copy, accent=accent)
            except ValueError as exc:
                console.print(f"[bold red]Error:[/bold red] {exc}")
                raise SystemExit(2)
        elif args.command == "crack":
            if not args.no_banner:
                render_banner(console, accent)
            if args.type != "auto" and args.type not in {"bcrypt", "argon2", "scrypt", "postgres"} and not is_hex_string(args.target_hash) and not args.target_hash.startswith("*") and not args.target_hash.lower().startswith("0x0100"):
                console.print("[bold red]Error:[/bold red] Hash must be hexadecimal (0-9, a-f).")
                raise SystemExit(2)
            if args.type == "auto":
                candidates = detect_hash_types(args.target_hash)
                if not candidates:
                    console.print("[bold red]Error:[/bold red] Unable to detect hash type.")
                    raise SystemExit(2)
                if len(candidates) > 1:
                    console.print(f"[bold yellow]Multiple candidates:[/bold yellow] {', '.join(candidates)}")
                    console.print("Use --type to select one.")
                    raise SystemExit(2)
                args.type = candidates[0]
            raise SystemExit(handle_crack(args, console, accent))
        else:
            parser.print_help()
    except KeyboardInterrupt:
        console.print(f"\n[bold {accent}]Goodbye[/bold {accent}]")
        raise SystemExit(0)
    except Exception:
        console.print("[bold red]Error:[/bold red] An unexpected error occurred. Please report this issue.")
        raise SystemExit(1)
