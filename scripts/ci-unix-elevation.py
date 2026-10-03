#!/usr/bin/env python3
"""Run sudo or native Keychain checks with a disposable account on hosted CI.

Invoke with the built zm path. The runner retains its passwordless sudo policy;
only a new standard account receives the temporary password-required rule.
The --keychain mode does not install a sudo rule for the fixture account.
"""
import os
import pathlib
import pwd
import secrets
import shutil
import subprocess
import sys
import tempfile


def run(*arguments, **kwargs):
    return subprocess.run(arguments, check=True, **kwargs)


def hosted_runner_only():
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise SystemExit("This account-provisioning script is restricted to GitHub-hosted runners.")


def provision_and_test(binary, harness, keychain=False):
    assert os.geteuid() == 0, "account provisioning requires root"
    username = "zmci" + secrets.token_hex(4)
    password = secrets.token_urlsafe(24)
    sudoers = pathlib.Path("/etc/sudoers.d") / username
    system = sys.platform
    assert system in ("darwin", "linux"), "macOS or Linux required"
    assert not keychain or system == "darwin", "native Keychain fixture requires macOS"
    assert sudoers.parent.is_dir(), "sudoers include directory is missing"
    account_created = False
    # macOS runner TMPDIR can have private ancestors owned by the runner.
    # The disposable account must be able to traverse the fixture's parent.
    with tempfile.TemporaryDirectory(prefix="zm-ci-sudo-", dir="/tmp") as directory:
        work = pathlib.Path(directory)
        home = work / "home"
        home.mkdir()
        try:
            if system == "darwin":
                used_ids = {account.pw_uid for account in pwd.getpwall()}
                uid = next(candidate for candidate in range(1000, 60000) if candidate not in used_ids)
                record = "/Users/" + username
                run("/usr/bin/dscl", ".", "-create", record)
                account_created = True
                for key, value in {
                    "UniqueID": str(uid), "PrimaryGroupID": "20", "UserShell": "/bin/bash",
                    "NFSHomeDirectory": str(home), "RealName": "ZManager CI sudo fixture",
                }.items():
                    run("/usr/bin/dscl", ".", "-create", record, key, value)
                # dscl's interactive command stream keeps the fixture password
                # off the process argument list and out of CI output.
                run("/usr/bin/dscl", ".", input=f"passwd {record} {password}\nquit\n", text=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                run("/usr/sbin/useradd", "--home-dir", str(home), "--shell", "/bin/bash", username)
                account_created = True
                run("/usr/sbin/chpasswd", input=f"{username}:{password}\n", text=True)
            account = pwd.getpwnam(username)
            if not keychain:
                candidate = work / "sudoers"
                candidate.write_text(f"{username} ALL=(root) PASSWD: ALL\n")
                candidate.chmod(0o440)
                run("/usr/sbin/visudo", "-cf", str(candidate), stdout=subprocess.DEVNULL)
                shutil.copyfile(candidate, sudoers)
                sudoers.chmod(0o440)
                # Validate only this fixture rule; runner-managed rules can
                # have different permissions. The harness proves active policy.
                run("/usr/sbin/visudo", "-cf", str(sudoers), stdout=subprocess.DEVNULL)
            # Copy into an accessible fixture directory: runner home directories
            # and build caches need not be readable by the disposable account.
            for source, name in [(binary, "zm"), (harness, harness.name)]:
                destination = work / name
                shutil.copyfile(source, destination)
                destination.chmod(0o755)
            for path in [work, home]:
                os.chown(path, account.pw_uid, account.pw_gid)
                path.chmod(0o700)
            environment = {
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home),
                "LANG": "en_US.UTF-8" if system == "darwin" else "C.UTF-8",
                "ZMANAGER_TEST_KEYCHAIN_PASSWORD" if keychain else "ZMANAGER_TEST_SUDO_PASSWORD": password,
                "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
            }
            print(f"Testing {'native Keychain recovery' if keychain else 'sudo authentication'} on {system}/{os.uname().machine}", flush=True)
            run(sys.executable, str(work / harness.name), str(work / "zm"),
                user=account.pw_uid, group=account.pw_gid, extra_groups=[], env=environment, cwd=home)
        finally:
            sudoers.unlink(missing_ok=True)
            if account_created:
                if system == "darwin":
                    run("/usr/bin/dscl", ".", "-delete", "/Users/" + username)
                else:
                    run("/usr/sbin/userdel", username)


def main():
    hosted_runner_only()
    if len(sys.argv) == 4 and sys.argv[1] in ("--provision", "--provision-keychain"):
        provision_and_test(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]), keychain=sys.argv[1] == "--provision-keychain")
    elif len(sys.argv) == 2 or (len(sys.argv) == 3 and sys.argv[1] == "--keychain"):
        keychain = len(sys.argv) == 3
        binary = pathlib.Path(sys.argv[-1]).resolve(strict=True)
        harness = pathlib.Path(__file__).with_name("test-macos-keychain.py" if keychain else "test-unix-elevation.py").resolve(strict=True)
        run("/usr/bin/sudo", "-n", "--", "/usr/bin/env", "GITHUB_ACTIONS=true", "RUNNER_ENVIRONMENT=github-hosted",
            sys.executable, str(pathlib.Path(__file__).resolve()), "--provision-keychain" if keychain else "--provision", str(binary), str(harness))
    else:
        raise SystemExit("Usage: ci-unix-elevation.py [--keychain] <built-zm>")


if __name__ == "__main__":
    main()
