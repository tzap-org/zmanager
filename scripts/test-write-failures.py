#!/usr/bin/env python3
"""Exercise actual ENOSPC and killed-process recovery on disposable filesystems."""
import contextlib
import errno
import os
import pathlib
import subprocess
import sys
import tempfile
import time


def run(arguments, success=True):
    result = subprocess.run(list(map(str, arguments)), capture_output=True, timeout=60)
    assert result.returncode == 0 if success else result.returncode != 0, result.stderr.decode(errors="replace")
    return result


@contextlib.contextmanager
def bounded_volume(root):
    mount = root / "bounded volume"
    mount.mkdir()
    if sys.platform == "darwin":
        image = root / "bounded.dmg"
        run(["hdiutil", "create", "-size", "32m", "-fs", "HFS+", "-volname", "ZManagerWriteFixture", image])
        run(["hdiutil", "attach", "-nobrowse", "-mountpoint", mount, image])
        detach = ["hdiutil", "detach", mount]
    elif sys.platform == "linux":
        prefix = [] if os.geteuid() == 0 else ["sudo", "-n"]
        if prefix and not (os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"):
            raise SystemExit("Linux bounded-filesystem tests require root in Docker or a GitHub-hosted runner.")
        run(prefix + ["mount", "-t", "tmpfs", "-o", f"size=16m,mode=0700,uid={os.getuid()},gid={os.getgid()}", "tmpfs", mount])
        detach = prefix + ["umount", mount]
    else:
        raise SystemExit("macOS or Linux required for this filesystem harness")
    try:
        capacity = os.statvfs(mount)
        assert capacity.f_blocks * capacity.f_frsize <= 64 * 1024 * 1024, "refusing to fill an unbounded filesystem"
        yield mount
    finally:
        run(detach)


def exhaust(volume):
    filler = volume / "disposable filler"
    with filler.open("wb", buffering=0) as output:
        try:
            while True:
                assert output.write(bytes(65536)) > 0
        except OSError as error:
            assert error.errno == errno.ENOSPC, f"unexpected fill error: {error}"
    return filler


def disk_full(binary, root, volume):
    source = root / "source with spaces 雪.txt"
    # Incompressible data exceeds filesystem metadata/clump reserves too.
    replacement = os.urandom(4 * 1024 * 1024)
    for extension in ("zip", "7z", "tar.zst"):
        destination = volume / ("existing." + extension)
        source.write_bytes(b"previous archive payload")
        run([binary, "create", destination, source, "--no-progress"])
        previous = destination.read_bytes()
        source.write_bytes(replacement)
        filler = exhaust(volume)
        command = [binary, "create", destination, source, "--force", "--no-progress"]
        try:
            result = run(command, success=False)
            assert b"space" in result.stderr.lower(), "the command did not report disk-full failure"
            assert destination.read_bytes() == previous, f"disk-full {extension} write replaced the original"
        finally:
            filler.unlink()
        run(command)
        run([binary, "test", destination, "--no-progress"])
        extracted = root / ("extracted-" + extension)
        run([binary, "extract", destination, "-C", extracted, "--no-progress"])
        assert (extracted / source.name).read_bytes() == source.read_bytes()
        destination.unlink()
        leftovers = [path for path in volume.iterdir() if path.name.startswith(".zmanager-") or ".tmp-" in path.name]
        assert not leftovers, "failed archive write left a temporary output"
        print(f"PASS: actual disk-full {extension} preservation and recovery", flush=True)


def interrupted(binary, root):
    source = root / "large source.bin"
    destination = root / "interrupted.zip"
    source.write_bytes(b"previous archive payload")
    run([binary, "create", destination, source, "--no-progress"])
    previous = destination.read_bytes()
    with source.open("wb") as output:
        output.truncate(256 * 1024 * 1024)
    diagnostics = (root / "interrupted-stderr.log").open("wb")
    process = subprocess.Popen([str(binary), "create", str(destination), str(source), "--force", "--no-progress"],
                               stdout=subprocess.DEVNULL, stderr=diagnostics)
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            # The CLI stages the destination before the engine stages its own
            # atomic file. Observe the real engine writer, including that prefix.
            temporary = list(root.glob(".zmanager-*.tmp"))
            writing = False
            for path in temporary:
                try:
                    writing |= path.stat().st_size > 0
                except FileNotFoundError:
                    pass
            if writing and process.poll() is None:
                process.kill()
                assert process.wait(timeout=10) != 0
                break
            assert process.poll() is None, f"archive exited before the interruption point: {(root / 'interrupted-stderr.log').read_text()}"
            time.sleep(0.001)
        else:
            raise AssertionError("no in-progress archive write observed")
        assert destination.read_bytes() == previous, "interrupted archive replaced the original"
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)
        diagnostics.close()
    # Recovery must work despite the uncommitted file left by SIGKILL, which
    # cannot run Rust Drop. All leftovers stay inside this disposable fixture.
    source.write_bytes(b"recovered after process interruption")
    run([binary, "create", destination, source, "--force", "--no-progress"])
    extracted = root / "interruption recovery"
    run([binary, "extract", destination, "-C", extracted, "--no-progress"])
    assert (extracted / source.name).read_bytes() == source.read_bytes()
    print("PASS: killed archive writer preserves original and restart succeeds", flush=True)


def main():
    binary = pathlib.Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="zm-write-failures-") as directory:
        root = pathlib.Path(directory)
        if "--interrupt-only" not in sys.argv[2:]:
            with bounded_volume(root) as volume:
                disk_full(binary, root, volume)
        interrupted(binary, root)


if __name__ == "__main__":
    main()
