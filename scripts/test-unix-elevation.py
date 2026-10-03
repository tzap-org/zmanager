#!/usr/bin/env python3
"""Exercise the real Unix CLI/sudo terminal flow using disposable fixtures.

Run as an unprivileged user. By default test cancellation and unattended modes.
Set ZMANAGER_TEST_SUDO_PASSWORD only for an isolated disposable test account to
exercise sudo authentication and extraction. Never supply a real user password.
"""
import os
import pathlib
import pty
import select
import signal
import subprocess
import sys
import tempfile
import time


def terminal_command(arguments, responses, initial_input=b""):
    pid, terminal = pty.fork()
    if pid == 0:
        os.execv(arguments[0], arguments)
    transcript = bytearray()
    pending = list(responses)
    deadline = time.monotonic() + 20
    status = None
    try:
        if initial_input:
            os.write(terminal, initial_input)
        while time.monotonic() < deadline:
            if select.select([terminal], [], [], 0.1)[0]:
                try:
                    chunk = os.read(terminal, 8192)
                except OSError:
                    break
                if not chunk:
                    break
                transcript.extend(chunk)
                if pending and pending[0][0] in transcript:
                    _, reply = pending.pop(0)
                    os.write(terminal, reply)
            ended, child_status = os.waitpid(pid, os.WNOHANG)
            if ended:
                status = child_status
                break
        else:
            raise AssertionError(f"terminal command timed out: {arguments}")
        if status is None:
            _, status = os.waitpid(pid, 0)
        assert not pending, "expected terminal prompt did not appear"
        return os.waitstatus_to_exitcode(status), bytes(transcript)
    finally:
        os.close(terminal)
        if status is None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass


def main():
    assert os.geteuid() != 0, "run this test as an unprivileged user"
    binary = str(pathlib.Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="zm-sudo-ux-") as directory:
        temp = pathlib.Path(directory)
        source = temp / "file with spaces 雪.txt"
        source.write_bytes(b"offline sudo extraction")
        archive = temp / "archive with spaces.zip"
        subprocess.run([binary, "create", str(archive), str(source), "--no-progress"], check=True, capture_output=True)
        protected = temp / "protected destination"
        protected.mkdir()
        protected.chmod(0o555)
        destination = protected / "new output"
        encrypted_destination = protected / "encrypted output"
        args = [binary, "extract", str(archive), "-C", str(destination), "--overwrite", "never", "--no-progress"]
        try:
            code, transcript = terminal_command(args, [(b"[y/N]", b"\n")])
            assert code != 0 and b"Extraction cancelled" in transcript
            assert not destination.exists(), "cancellation wrote files"
            code, transcript = terminal_command(args, [(b"[y/N]", b"maybe\nyes-no\nn\n")])
            assert code != 0 and b"Please answer yes or no" in transcript
            assert not destination.exists()
            for flags in [[], ["--json"], ["--quiet"], ["--no-password-prompt"], ["--password-stdin"]]:
                result = subprocess.run(args + flags, input=b"\n", capture_output=True, timeout=10)
                assert result.returncode != 0
                assert b"[y/N]" not in result.stderr and b"sudo password" not in result.stderr
                assert not destination.exists()
            for flags in [["--json"], ["--quiet"], ["--no-password-prompt"], ["--password-stdin"]]:
                code, transcript = terminal_command(args + flags, [], b"\n" if "--password-stdin" in flags else b"")
                assert code != 0 and b"[y/N]" not in transcript
                assert not destination.exists()
            password = os.environ.get("ZMANAGER_TEST_SUDO_PASSWORD")
            if password is not None:
                assert password, "fixture sudo password must not be empty"
                def fixture_sudo(command):
                    subprocess.run(["/usr/bin/sudo", "-k"], check=True)
                    code, output = terminal_command(
                        ["/usr/bin/sudo", "-p", "[zm-test] password: ", "--"] + command,
                        [(b"[zm-test] password:", password.encode() + b"\n")],
                    )
                    assert code == 0, "fixture sudo command failed"
                    assert password.encode() not in output, "sudo echoed the fixture password"

                subprocess.run(["/usr/bin/sudo", "-k"], check=True)
                unattended = subprocess.run(["/usr/bin/sudo", "-n", "true"], capture_output=True)
                assert unattended.returncode != 0, "fixture account must require a sudo password"
                code, cancelled = terminal_command(args, [(b"[y/N]", b"y\n"), (b"[zm] sudo password", b"\x03")])
                assert code != 0, "interrupting sudo authentication must fail"
                assert not destination.exists(), "cancelled authentication wrote files"
                assert b"Sudo extraction failed or was cancelled" not in cancelled
                subprocess.run(["/usr/bin/sudo", "-k"], check=True)
                code, transcript = terminal_command(args, [(b"[y/N]", b"y\n"), (b"[zm] sudo password", password.encode() + b"\n")])
                assert code == 0, "sudo extraction failed"
                assert b"sudo password" in transcript
                assert password.encode() not in transcript, "sudo echoed the fixture password"
                assert (destination / source.name).read_bytes() == source.read_bytes()
                # A second elevated extraction must retain --overwrite never.
                fixture_sudo(["/bin/chmod", "666", str(destination / source.name)])
                (destination / source.name).write_bytes(b"keep existing contents")
                subprocess.run(["/usr/bin/sudo", "-k"], check=True)
                code, rejected = terminal_command(args, [(b"[y/N]", b"y\n"), (b"[zm] sudo password", password.encode() + b"\n")])
                assert code != 0 and b"would overwrite" in rejected, "sudo retry must reject the existing file under --overwrite never"
                assert b"Sudo extraction failed or was cancelled" not in rejected, "a generic sudo failure must not obscure the extraction error"
                assert (destination / source.name).read_bytes() == b"keep existing contents"
                print("PASS: expected overwrite rejection; existing contents preserved")
                archive_password = b"fixture-only-archive-password"
                encrypted_archive = temp / "encrypted archive.zip"
                subprocess.run(
                    [binary, "create", str(encrypted_archive), str(source), "--encrypt", "--password-stdin", "--no-progress"],
                    input=archive_password + b"\n", check=True, capture_output=True,
                )
                subprocess.run(["/usr/bin/sudo", "-k"], check=True)
                code, output = terminal_command(
                    [binary, "extract", str(encrypted_archive), "-C", str(encrypted_destination), "--no-progress"],
                    [(b"[y/N]", b"y\n"), (b"[zm] sudo password", password.encode() + b"\n"), (b"Archive password:", archive_password + b"\n")],
                )
                assert code == 0, "encrypted sudo extraction failed"
                assert archive_password not in output and password.encode() not in output, "a password was echoed"
                assert (encrypted_destination / source.name).read_bytes() == source.read_bytes()
                subprocess.run(["/usr/bin/sudo", "-k"], check=True)
            print("Unix elevation UX passed" + (" including sudo password authentication" if password else " (consent, cancellation, unattended modes)"))
        finally:
            if os.environ.get("ZMANAGER_TEST_SUDO_PASSWORD") is not None:
                for output in [destination, encrypted_destination]:
                    if output.exists():
                        fixture_sudo(["/usr/bin/python3", "-c", "import shutil,sys;shutil.rmtree(sys.argv[1])", str(output)])
                subprocess.run(["/usr/bin/sudo", "-k"], check=True)
            protected.chmod(0o755)


if __name__ == "__main__":
    main()
