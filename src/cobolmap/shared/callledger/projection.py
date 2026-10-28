"""Append-only JSONL projection of an already verified SQLite event snapshot."""
from contextlib import contextmanager
import os
from pathlib import Path

from .models import LedgerError


@contextmanager
def _exclusive(stream):
    """Nonblocking OS file lock; no stale sidecar or deleted lock artifact."""
    stream.seek(0)
    if os.name == "nt":
        import msvcrt
        try:
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as error:
            raise LedgerError("projection_busy", "Projection is locked; no write performed") from error
        try:
            yield
        finally:
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise LedgerError("projection_busy", "Projection is locked; no write performed") from error
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def export_jsonl(path: Path, events: list[dict], *, protected_database: Path):
    from .ledger import encoded
    if str(path).startswith(("\\\\", "//")) or str(path).startswith("file:"):
        raise LedgerError("projection_path", "Local filesystem projection only")
    absolute = path.absolute()
    if any(part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()) for part in (absolute, *absolute.parents)):
        raise LedgerError("projection_path", "Linked projection path refused")
    database = protected_database.resolve()
    protected = [database, Path(str(database) + "-wal"), Path(str(database) + "-shm"), Path(str(database) + "-journal")]
    for candidate in protected:
        if path.resolve() == candidate or (path.exists() and candidate.exists() and os.path.samefile(path, candidate)):
            raise LedgerError("projection_path", "Projection cannot target SQLite or its journal")
    lines = [(encoded(event) + "\n").encode("utf-8") for event in events]
    try:
        with path.open("a+b") as stream, _exclusive(stream):
            stream.seek(0)
            existing = 0
            for expected in lines:
                actual = stream.readline()
                if not actual:
                    break
                if actual != expected:
                    raise LedgerError("projection_divergence", "Protected history differs or is partial; never rewritten")
                existing += 1
            if stream.read(1):
                raise LedgerError("projection_divergence", "Projection contains events absent from SQLite")
            stream.seek(0, os.SEEK_END)
            for line in lines[existing:]:
                stream.write(line)
            stream.flush()
            os.fsync(stream.fileno())
            return {"event_count": len(lines), "appended": len(lines) - existing,
                    "last_sha256": events[-1]["sha256"], "backend_status": "backend_unverified"}
    except OSError as error:
        raise LedgerError("projection_io", "Projection may be incomplete; SQLite remains authoritative; preserve file") from error
