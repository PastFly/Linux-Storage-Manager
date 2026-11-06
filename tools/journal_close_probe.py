"""Disposable Linux CI probe for unnamed staging inode close notifications."""

import ctypes
import os
import struct
import tempfile
from pathlib import Path

libc = ctypes.CDLL(None, use_errno=True)
AT_FDCWD = -100
AT_SYMLINK_FOLLOW = 0x400
IN_CLOSE_WRITE = 0x8


def check(result):
    if result < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return result


with tempfile.TemporaryDirectory(prefix="lsm-close-probe-") as temporary:
    root = Path(temporary)
    journal = root / "journal"
    journal.mkdir(mode=0o700)
    for label, staging in (("journal", journal), ("parent", root)):
        writer = os.open(staging, os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC, 0o600)
        os.write(writer, b"record\n")
        os.fsync(writer)
        source = os.fsencode(f"/proc/self/fd/{writer}")
        target = os.fsencode(journal / f"{label}.json")
        check(libc.linkat(AT_FDCWD, source, AT_FDCWD, target, AT_SYMLINK_FOLLOW))
        inherited = os.dup(writer)
        os.close(writer)
        watch = check(libc.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK))
        check(libc.inotify_add_watch(watch, os.fsencode(journal), IN_CLOSE_WRITE))
        os.close(inherited)
        try:
            data = os.read(watch, 4096)
        except BlockingIOError:
            data = b""
        events = []
        while data:
            _, mask, _, length = struct.unpack_from("iIII", data)
            events.append((hex(mask), os.fsdecode(data[16 : 16 + length].rstrip(b"\0"))))
            data = data[16 + length :]
        print(f"{label} staging: {events}")
        os.close(watch)
