#!/usr/bin/env python3
"""Unpack the actual offline distribution and exercise its installed executable."""
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile


def safe_path(name):
    path = pathlib.PurePosixPath(name.replace("\\", "/"))
    assert not path.is_absolute() and ".." not in path.parts and ":" not in name, f"unsafe package entry: {name}"


def unpack(archive, destination):
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as package:
            for member in package.infolist():
                safe_path(member.filename)
                assert (member.external_attr >> 16) & 0o170000 != 0o120000, "package symlinks are not supported"
            package.extractall(destination)
    else:
        with tarfile.open(archive) as package:
            for member in package.getmembers():
                safe_path(member.name)
                assert member.isfile() or member.isdir(), "package must contain only regular files/directories"
            if hasattr(tarfile, "data_filter"):
                package.extractall(destination, filter="data")
            else:
                package.extractall(destination)


def exercise(binary, directory):
    home = directory / "fresh home"
    home.mkdir()
    environment = os.environ.copy()
    environment.update(HOME=str(home), USERPROFILE=str(home), APPDATA=str(home / "roaming"), LOCALAPPDATA=str(home / "local"))
    # The installed executable must work without development tools or another zm.
    environment["PATH"] = str(binary.parent)
    first_launch_command = ["zm", "--version"]
    if sys.platform == "win32":
        # os.environ performs Windows' case-insensitive lookup; its dict copy does not.
        system_directory = pathlib.Path(os.environ["SystemRoot"]) / "System32"
        environment["PATH"] += os.pathsep + str(system_directory)
        # CreateProcess searches the parent's PATH. cmd searches the child's fresh PATH.
        first_launch_command = [str(system_directory / "cmd.exe"), "/d", "/c", "zm --version"]

    def run(*arguments, password=None, success=True):
        result = subprocess.run([str(binary), *map(str, arguments)], cwd=directory, env=environment,
                                input=password, capture_output=True, timeout=30)
        assert result.returncode == 0 if success else result.returncode != 0, f"{arguments[0]}: {result.stderr.decode(errors='replace')}"
        if password:
            assert password.strip() not in result.stdout + result.stderr, "archive password was echoed"
        return result

    first_launch = subprocess.run(first_launch_command, cwd=directory, env=environment, capture_output=True, timeout=30)
    assert first_launch.returncode == 0, "installed zm was not executable through the fresh PATH"
    version = first_launch.stdout.decode()
    assert re.search(r"\(offline(?:,|\))", version), "package contains the wrong build flavor"
    assert run("--version").stdout == first_launch.stdout, "PATH resolved a different executable"
    doctor = json.loads(run("doctor", "--json").stdout)
    assert doctor["ready"] is True and doctor["engine"] == "zmanager-core", "installed engine is not ready"
    run("auth", "login", success=False)
    state = home / "identity"
    certificates = json.loads(run("tzap", "certs", "--state-dir", state, "--json").stdout)
    assert certificates["certificates"] == [] and not state.exists(), "first launch changed the fresh identity state"
    source = directory / "payload with spaces 雪.txt"
    contents = b"offline packaged executable\n" * 100
    source.write_bytes(contents)
    archive = directory / "encrypted archive.zip"
    password = b"disposable-package-fixture-password\n"
    run("create", archive, source, "--encrypt", "--password-stdin", "--no-progress", password=password)
    run("test", archive, "--password-stdin", "--no-progress", password=password)
    run("list", archive, "--password-stdin", "--json", password=password)
    extracted = directory / "extracted"
    run("extract", archive, "-C", extracted, "--password-stdin", "--no-progress", password=password)
    assert (extracted / source.name).read_bytes() == contents
    run("extract", archive, "-C", extracted, "--overwrite", "never", "--password-stdin", "--no-progress", password=password, success=False)
    assert (extracted / source.name).read_bytes() == contents
    streamed = run("extract", archive, "--to-stdout", "--password-stdin", "--no-progress", password=password)
    assert streamed.stdout == contents
    for shell in ("bash", "zsh", "fish", "powershell"):
        assert run("completions", shell).stdout, f"missing {shell} completion"
    print(f"PASS: installed offline package on {sys.platform}; {version.strip()}", flush=True)


def main():
    archive = pathlib.Path(sys.argv[1]).resolve(strict=True)
    checksum = archive.with_name(archive.name + ".sha256")
    expected = checksum.read_text().split()[0]
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == expected, "package checksum mismatch"
    # GitHub's Windows TEMP can resolve through an 8.3 short user path. The
    # firewall program filter requires the full executable path; use the
    # runner-owned temp root so the installed package path stays canonical.
    temporary_root = os.environ.get("RUNNER_TEMP") if sys.platform == "win32" else None
    if temporary_root and not os.path.isdir(temporary_root):
        temporary_root = None
    with tempfile.TemporaryDirectory(prefix="zm-package-", dir=temporary_root) as directory:
        root = pathlib.Path(directory)
        installed = root / "installed"
        installed.mkdir()
        unpack(archive, installed)
        for name in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md", "completions/zm.bash", "completions/_zm", "completions/zm.fish", "completions/zm.ps1", "man/man1/zm.1"):
            assert (installed / name).is_file(), f"missing packaged file: {name}"
        binary = installed / ("zm.exe" if sys.platform == "win32" else "zm")
        assert binary.is_file(), "offline executable is missing"
        exercise(binary, root)
        if len(sys.argv) > 2:
            assert sys.argv[2] == "--workflow" and len(sys.argv) > 3, "expected --workflow followed by a test command"
            environment = os.environ.copy()
            environment["ZMANAGER_AUDIT_BINARY"] = str(binary)
            subprocess.run(sys.argv[3:], env=environment, check=True)
            print("PASS: offline identity workflow against the checksum-verified installed executable", flush=True)


if __name__ == "__main__":
    main()
