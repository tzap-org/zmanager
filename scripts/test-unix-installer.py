#!/usr/bin/env python3
"""Run the real installer against local release assets and a failing native cp."""
import hashlib
import json
import os
import pathlib
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time


def main():
    archive = pathlib.Path(sys.argv[1]).resolve(strict=True)
    installer = pathlib.Path(__file__).resolve().parent.parent / "install.sh"
    with tempfile.TemporaryDirectory(prefix="zm-installer-") as directory:
        root = pathlib.Path(directory)
        repository = root / "release fixture"
        release = repository / "releases" / "download" / "fixture"
        release.mkdir(parents=True)
        shutil.copyfile(archive, release / archive.name)
        checksum = release / "SHA256SUMS"
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        checksum.write_text(f"{digest}  {archive.name}\n")
        home = root / "fresh home"
        home.mkdir()
        destination = home / "bin with spaces 雪"
        environment = os.environ.copy()
        environment.update(HOME=str(home), ZMANAGER_REPO_URL=repository.as_uri(), ZMANAGER_VERSION="fixture", ZMANAGER_INSTALL_DIR=str(destination))

        def install(success, environment=environment):
            result = subprocess.run(["sh", str(installer)], cwd=root, env=environment, capture_output=True, timeout=60)
            assert result.returncode == 0 if success else result.returncode != 0, result.stderr.decode(errors="replace")
            return result

        installed = install(True)
        binary = destination / "zm"
        previous = binary.read_bytes()
        assert binary.stat().st_mode & 0o111, "installer did not mark the binary executable"
        assert b"PATH" in installed.stdout, "fresh install did not explain PATH setup"
        first_launch = subprocess.run(["zm", "--version"], env={**environment, "PATH": str(destination)}, capture_output=True, timeout=30)
        assert first_launch.returncode == 0 and b"(offline" in first_launch.stdout
        doctor = subprocess.run([str(binary), "doctor", "--json"], env=environment, capture_output=True, timeout=30)
        assert doctor.returncode == 0 and json.loads(doctor.stdout)["ready"] is True
        checksum.write_text(f"{'0' * 64}  {archive.name}\n")
        rejected = install(False)
        assert b"checksum mismatch" in rejected.stderr
        assert binary.read_bytes() == previous, "checksum rejection changed the existing installation"
        checksum.write_text(f"{digest}  {archive.name}\n")

        if os.geteuid() != 0:
            destination.chmod(0o555)
            try:
                permission = install(False)
                assert b"cannot write" in permission.stderr and b"sudo env" in permission.stderr
                assert f'ZMANAGER_INSTALL_DIR="{destination}"'.encode() in permission.stderr
                assert binary.read_bytes() == previous, "permission refusal changed the existing installation"
            finally:
                destination.chmod(0o755)
            print("PASS: unwritable installation explains sudo and preserves the executable", flush=True)
        else:
            print("SKIP: install permission refusal requires an unprivileged user", flush=True)

        wrappers = root / "copy failure"
        wrappers.mkdir()
        native_copy = shutil.which("cp")
        assert native_copy, "native cp is required"
        injection = wrappers / "copy-injection.py"
        injection.write_text("import resource, signal, subprocess, sys\n"
                             "signal.signal(signal.SIGXFSZ, signal.SIG_IGN)\n"
                             "resource.setrlimit(resource.RLIMIT_FSIZE, (1024, 1024))\n"
                             f"sys.exit(subprocess.call([{native_copy!r}, *sys.argv[1:]], restore_signals=False))\n")
        wrapper = wrappers / "cp"
        wrapper.write_text(f"#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(injection))} \"$@\"\n")
        wrapper.chmod(0o755)
        failed = install(False, {**environment, "PATH": str(wrappers) + os.pathsep + environment["PATH"]})
        assert binary.read_bytes() == previous, "partial native copy destroyed the existing installation"
        assert b"File too large" in failed.stderr or b"file too large" in failed.stderr
        assert not list(destination.glob(".zm-install.*")), "failed installation left its temporary executable"
        ready = root / "copy-completed"
        injection.write_text("import pathlib, signal, subprocess, sys\n"
                             f"subprocess.run([{native_copy!r}, *sys.argv[1:]], check=True)\n"
                             f"pathlib.Path({str(ready)!r}).write_text('ready')\n"
                             "signal.pause()\n")
        process = subprocess.Popen(["sh", str(installer)], cwd=root,
                                   env={**environment, "PATH": str(wrappers) + os.pathsep + environment["PATH"]},
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            deadline = time.monotonic() + 15
            while not ready.exists():
                assert process.poll() is None and time.monotonic() < deadline, "installer did not reach the staged-copy interruption point"
                time.sleep(0.01)
            os.killpg(process.pid, signal.SIGTERM)
            process.communicate(timeout=10)
            assert process.returncode != 0, "interrupted installer reported success"
            assert binary.read_bytes() == previous, "interrupted update replaced the existing executable"
            assert not list(destination.glob(".zm-install.*")), "interrupted installation left its temporary executable"
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
            process.stdout.close()
            process.stderr.close()
        install(True)
        assert binary.read_bytes() == previous
        print("PASS: real Unix installer, fresh PATH launch, checksum refusal, partial copy and interruption preservation, retry", flush=True)


if __name__ == "__main__":
    main()
