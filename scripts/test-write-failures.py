#!/usr/bin/env python3
"""Exercise actual ENOSPC and killed-process recovery on disposable filesystems."""
import contextlib
import errno
import json
import os
import pathlib
import shutil
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
    elif sys.platform == "win32":
        helper = pathlib.Path(__file__).with_name("test-windows-bounded-volume.ps1").resolve(strict=True)
        image = root / "bounded.vhd"
        command = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", helper,
                   "-ImagePath", image, "-MountPath", mount]
        try:
            run(command)
            assert shutil.disk_usage(mount).total <= 64 * 1024 * 1024, "refusing to fill an unbounded Windows filesystem"
            yield mount
        finally:
            run(command + ["-Detach"])
        return
    else:
        raise SystemExit("macOS, Linux or Windows required for this filesystem harness")
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


def disk_full_export(binary, arguments, trust_root, root, volume):
    output_index = arguments.index("--output") + 1
    previous = pathlib.Path(arguments[output_index]).read_bytes()
    destination = volume / "existing signed export with spaces 雪.json"
    destination.write_bytes(previous)
    arguments[output_index] = str(destination)
    state = pathlib.Path(arguments[arguments.index("--state-dir") + 1])
    catalogue = state / "default.identity-catalog.json"
    original_catalogue = catalogue.read_bytes()
    command = [binary, *arguments]
    filler = exhaust(volume)
    reserves = []
    try:
        # HFS+ can reject the large filler's next allocation clump while still
        # admitting a small new file. Consume that real remaining capacity too.
        for number in range(16384):
            reserved = volume / f"small allocation filler {number}"
            reserves.append(reserved)
            try:
                with reserved.open("wb", buffering=0) as output:
                    output.write(bytes(4096))
            except OSError as error:
                assert error.errno == errno.ENOSPC, f"unexpected reserve fill error: {error}"
                break
        else:
            raise AssertionError("bounded volume still accepts small allocations after 64 MiB")
        failed = run(command, success=False)
        assert b"space" in (failed.stdout + failed.stderr).lower(), "export did not report actual disk-full failure"
        assert destination.read_bytes() == previous, "disk-full export replaced the original"
        assert catalogue.read_bytes() == original_catalogue, "failed export changed the identity catalogue"
    finally:
        for reserved in reserves:
            reserved.unlink(missing_ok=True)
        filler.unlink()
    run(command)
    assert catalogue.read_bytes() == original_catalogue, "export retry changed the identity catalogue"
    assert not list(volume.glob("*.tmp-*")), "failed export left a temporary output"
    if arguments[:2] == ["tzap", "sign"]:
        verified = run([binary, "tzap", "verify", destination, "--custom-trust-root-cert", trust_root, "--json"])
        assert json.loads(verified.stdout)["state"] == "cryptographically_intact_offline"
    else:
        assert arguments[:3] == ["tzap", "contact", "export"], "unsupported export fixture"
        run([binary, "tzap", "contact", "import", destination, "--custom-trust-root-cert", trust_root,
             "--accept", "--state-dir", root / "verification state", "--json"])
    print("PASS: actual disk-full signed export preserves output/catalogue; retry verifies", flush=True)


def main():
    if sys.argv[1] == "--export":
        trust_root = pathlib.Path(sys.argv[2]).resolve(strict=True)
        binary = pathlib.Path(sys.argv[3]).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix="zm-export-disk-full-") as directory:
            root = pathlib.Path(directory)
            with bounded_volume(root) as volume:
                disk_full_export(binary, sys.argv[4:], trust_root, root, volume)
        return
    binary = pathlib.Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="zm-write-failures-") as directory:
        root = pathlib.Path(directory)
        if "--interrupt-only" not in sys.argv[2:]:
            with bounded_volume(root) as volume:
                disk_full(binary, root, volume)
        interrupted(binary, root)


if __name__ == "__main__":
    main()
