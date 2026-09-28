import os
import subprocess
import sys
from pathlib import Path
from typing import Optional, Sequence


_PKG_DIR = Path(__file__).resolve().parent       # hashsmith/ package dir
_GO_ROOT = _PKG_DIR / "go_hashsmith"             # go sources bundled inside the package
_GO_BIN_DIR = Path.home() / ".hashsmith-go"      # compiled binary stored in user home
_GO_BIN = _GO_BIN_DIR / ("hashsmith.exe" if os.name == "nt" else "hashsmith")


def _package_version() -> str:
    """The installed distribution's version, or "dev" outside an install."""
    try:
        from importlib.metadata import PackageNotFoundError, version
    except ImportError:  # pragma: no cover - Python < 3.8
        return "dev"
    try:
        return version("hashsmith-cli")
    except PackageNotFoundError:
        return "dev"


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
            env = {**os.environ, "GOWORK": "off"}
            # Stamp the distribution's own version into the binary, so a
            # pip-installed hashsmith can answer --version with something
            # better than "dev". Without this the built binary has no way to
            # know which release it came from, because it is compiled on the
            # user's machine from an sdist that carries no VCS metadata.
            ldflags = f"-X main.version={_package_version()}"
            subprocess.run(
                ["go", "build", "-ldflags", ldflags, "-o", str(_GO_BIN), "./cmd/hashsmith"],
                cwd=str(_GO_ROOT),
                env=env,
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


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
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
