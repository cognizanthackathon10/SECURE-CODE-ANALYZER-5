

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterator, Optional

DEFAULT_MAX_BYTES = 50 * 1024 * 1024  


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("safe_file_summary")



@dataclass(frozen=True)
class FileStats:
    path: str
    resolved_path: str
    bytes: int
    lines: int
    words: int
    sha256: str



def iter_file_in_chunks(file_path: Path, chunk_size: int = 8192) -> Iterator[bytes]:
    """
    Yield bytes from file in chunks. Uses binary mode to compute hash safely.
    """
    with file_path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk


def compute_sha256(file_path: Path) -> str:
    """
    Compute SHA-256 hash of a file in a streaming fashion.
    Returns the hexadecimal digest.
    """
    hasher = hashlib.sha256()
    for chunk in iter_file_in_chunks(file_path):
        hasher.update(chunk)
    return hasher.hexdigest()


def safe_text_line_iterator(file_path: Path, encoding: str = "utf-8", errors: str = "replace"):
    """
    Iterate over lines in a file using text mode with a safe fallback for encoding errors.
    'replace' prevents raising on invalid bytes and replaces them with the Unicode replacement character.
    """
    with file_path.open("r", encoding=encoding, errors=errors) as f:
        for line in f:
            yield line


def atomic_write_json(obj, out_path: Path, *, mode=0o600) -> None:
    """
    Write obj as JSON to out_path atomically using a temporary file then os.replace.
    Mode defaults to owner read/write only (0o600) to avoid making files world-readable.
    """
    json_text = json.dumps(obj, ensure_ascii=False, indent=2)
    out_dir = out_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)


    fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", dir=str(out_dir))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json_text)
            f.flush()
            os.fsync(f.fileno())

        try:
            os.chmod(tmp_path, mode)
        except Exception:

            logger.debug("Could not chmod temp file %s", tmp_path)

        os.replace(tmp_path, str(out_path))
    except Exception:

        try:
            os.remove(tmp_path)
        except Exception:
            pass
        raise


def generate_stats(file_path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> FileStats:
    """
    Generate FileStats for the given file path.
    Validates that the path is a regular file and that its size is within allowed limits.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    if not file_path.is_file():
        raise ValueError(f"Not a regular file: {file_path}")

    resolved = file_path.resolve()

    try:
        size = resolved.stat().st_size
    except OSError as e:
        raise OSError(f"Could not stat file {resolved}: {e}") from e

    if size > max_bytes:
        raise ValueError(
            f"File {resolved} is too large ({size} bytes). "
            f"Increase --max-bytes if you really want to process it."
        )


    lines = 0
    words = 0

    for line in safe_text_line_iterator(resolved):
        lines += 1

        words += len(line.split())


    sha256 = compute_sha256(resolved)

    return FileStats(
        path=str(file_path),
        resolved_path=str(resolved),
        bytes=size,
        lines=lines,
        words=words,
        sha256=sha256,
    )


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="safe_file_summary",
        description="Compute safe summary statistics for a text file and optionally write a JSON summary.",
    )
    p.add_argument("file", type=Path, help="Path to the input text file")
    p.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        help=f"Maximum number of bytes to process (default {DEFAULT_MAX_BYTES} bytes).",
    )
    p.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="Optional path to write JSON summary atomically. Will use secure permissions (owner read/write).",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress info logging; only errors will be shown.",
    )
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)

    if args.quiet:
        logger.setLevel(logging.ERROR)

    try:
        stats = generate_stats(args.file, max_bytes=args.max_bytes)
    except Exception as exc:
        logger.error("Failed to generate stats: %s", exc)
        return 2


    print("File summary:")
    print(f"  Path: {stats.path}")
    print(f"  Resolved path: {stats.resolved_path}")
    print(f"  Size (bytes): {stats.bytes}")
    print(f"  Lines: {stats.lines}")
    print(f"  Words: {stats.words}")
    print(f"  SHA-256: {stats.sha256}")

    if args.output_json:
        output_obj = asdict(stats)
        try:
            atomic_write_json(output_obj, args.output_json)
            logger.info("Wrote JSON summary to %s", args.output_json)
        except Exception as exc:
            logger.error("Failed to write JSON output: %s", exc)
            return 3

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
