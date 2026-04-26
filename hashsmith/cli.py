import os
import subprocess
import sys
from pathlib import Path
from typing import Optional, Sequence


_ROOT = Path(__file__).resolve().parents[1]
_GO_ROOT = _ROOT / "go_hashsmith"
_GO_BIN_DIR = _ROOT / ".hashsmith-go"
_GO_BIN = _GO_BIN_DIR / ("hashsmith.exe" if os.name == "nt" else "hashsmith")


def _go_sources_mtime() -> float:
    latest = 0.0
    for path in _GO_ROOT.rglob("*.go"):
        latest = max(latest, path.stat().st_mtime)
    mod = _GO_ROOT / "go.mod"
    if mod.exists():
        latest = max(latest, mod.stat().st_mtime)
    return latest


def ensure_go_binary() -> Path:
    if not _GO_ROOT.exists():
        raise RuntimeError("Go backend source directory not found")

    need_build = not _GO_BIN.exists()
    if not need_build:
        need_build = _GO_BIN.stat().st_mtime < _go_sources_mtime()

    if need_build:
        _GO_BIN_DIR.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.run(
                ["go", "build", "-o", str(_GO_BIN), "./cmd/hashsmith"],
                cwd=str(_GO_ROOT),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("Go compiler was not found. Please install Go 1.21+.") from exc
        except subprocess.CalledProcessError as exc:
            msg = exc.stderr.strip() or exc.stdout.strip() or "Unknown Go build error"
            raise RuntimeError(f"Failed to build Go backend: {msg}") from exc

    return _GO_BIN


def _normalize_args(argv: Sequence[str]) -> list[str]:
    args = list(argv)
    if args and args[0] in {"-id", "--identify"}:
        return ["identify", *args[1:]]
    return args


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _normalize_args(sys.argv[1:] if argv is None else argv)
    try:
        binary = ensure_go_binary()
    except RuntimeError as exc:
        print(f"hashsmith: {exc}", file=sys.stderr)
        return 2

    try:
        proc = subprocess.run([str(binary), *args])
        return proc.returncode
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
