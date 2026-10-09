#!/usr/bin/python3
"""Create a persistent admission seed as the service user; never rotate on upgrade."""
import os
from pathlib import Path
import secrets
import stat
import sys
import tempfile


def ensure(path):
    path = Path(path)
    parent = path.parent
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("seed directory must be owned by the service user with mode 0700")
    def validate():
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError("seed must be a private regular file owned by the service user")
            data = os.read(fd, 66)
            if len(data) != 32 and not (len(data) == 64 and all(c in b"0123456789abcdefABCDEF" for c in data)):
                raise ValueError("seed must contain 32 raw bytes or 64 hexadecimal characters")
        finally:
            os.close(fd)
    if path.exists() or path.is_symlink():
        validate()
        return
    fd, temporary = tempfile.mkstemp(prefix=".admission-", dir=parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(secrets.token_bytes(32))
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            pass
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        validate()
    finally:
        os.unlink(temporary)


if __name__ == "__main__":
    try:
        ensure(sys.argv[1])
    except (OSError, ValueError, IndexError) as error:
        sys.exit(f"sibuna-seed: {error}")
