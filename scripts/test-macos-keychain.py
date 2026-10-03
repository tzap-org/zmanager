#!/usr/bin/env python3
"""Native Keychain recovery, restricted to a disposable hosted-runner account."""
import ctypes
import json
import os
import pathlib
import pwd
import re
import subprocess
import sys

USER_KEYCHAIN_DOMAIN = 0  # kSecPreferencesDomainUser from SecKeychain.h


def security(*arguments, password=None):
    if password is None:
        command, data = ["/usr/bin/security", *map(str, arguments)], None
    else:
        # The random fixture password is passed on stdin, never in process argv.
        assert all(re.fullmatch(r"[A-Za-z0-9/_.-]+", str(value)) for value in arguments)
        command = ["/usr/bin/security", "-i"]
        data = (" ".join(map(str, arguments)) + "\n").encode()
    result = subprocess.run(command, input=data, capture_output=True, timeout=15)
    if password is not None:
        assert password.encode() not in result.stdout + result.stderr, "fixture password was echoed"
    assert result.returncode == 0, "fixture security command failed"
    return result.stdout


def is_unlocked(path):
    framework = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
    core = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    framework.SecKeychainOpen.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
    framework.SecKeychainOpen.restype = ctypes.c_int32
    framework.SecKeychainGetStatus.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    framework.SecKeychainGetStatus.restype = ctypes.c_int32
    core.CFRelease.argtypes = [ctypes.c_void_p]
    core.CFRelease.restype = None
    keychain, status = ctypes.c_void_p(), ctypes.c_uint32()
    assert framework.SecKeychainOpen(os.fsencode(path), ctypes.byref(keychain)) == 0
    try:
        assert framework.SecKeychainGetStatus(keychain, ctypes.byref(status)) == 0
        return bool(status.value & 1)  # kSecUnlockStateStatus from SecKeychain.h
    finally:
        core.CFRelease(keychain)


def assert_native_default(path):
    framework = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
    core = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    framework.SecKeychainCopyDomainDefault.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    framework.SecKeychainCopyDomainDefault.restype = ctypes.c_int32
    framework.SecKeychainGetPath.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
    framework.SecKeychainGetPath.restype = ctypes.c_int32
    core.CFRelease.argtypes = [ctypes.c_void_p]
    core.CFRelease.restype = None
    keychain = ctypes.c_void_p()
    result = framework.SecKeychainCopyDomainDefault(USER_KEYCHAIN_DOMAIN, ctypes.byref(keychain))
    assert result == 0, f"native user-domain default Keychain lookup failed: OSStatus {result}"
    try:
        buffer = ctypes.create_string_buffer(4096)
        length = ctypes.c_uint32(len(buffer))
        result = framework.SecKeychainGetPath(keychain, ctypes.byref(length), buffer)
        assert result == 0, f"native default Keychain path lookup failed: OSStatus {result}"
        assert pathlib.Path(os.fsdecode(buffer.value)).resolve() == path.resolve(), "native backend selected a different Keychain"
        print("PASS: native user-domain default Keychain matches the private fixture", flush=True)
    finally:
        core.CFRelease(keychain)


def main():
    assert sys.platform == "darwin" and os.geteuid() != 0
    assert os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    account = pwd.getpwuid(os.geteuid())
    assert re.fullmatch(r"zmci[0-9a-f]{8}", account.pw_name), "requires an isolated CI account"
    home = pathlib.Path(os.environ["HOME"]).resolve()
    assert home == pathlib.Path(account.pw_dir).resolve() and home.stat().st_uid == os.geteuid()
    binary = pathlib.Path(sys.argv[1]).resolve(strict=True)
    password = os.environ["ZMANAGER_TEST_KEYCHAIN_PASSWORD"]
    state = home / "identity"

    def keygen(success, state_directory=state):
        command = [str(binary), "tzap", "contact", "keygen", "--state-dir", str(state_directory), "--json"]
        result = subprocess.run(command, capture_output=True, timeout=20)
        assert password.encode() not in result.stdout + result.stderr, "fixture password was echoed"
        response = json.loads(result.stdout)
        expected = "success" if success else "failure"
        assert (result.returncode == 0) == success, (
            f"native key generation expected {expected}, exit {result.returncode}: "
            f"{response.get('error', 'no error diagnostic')}"
        )
        if success:
            assert response["generated"] is True
        else:
            assert response["ok"] is False and "secure secret store" in response["error"], response
        return response

    # This account has never created a Keychain. Failure must not publish a key.
    unavailable = keygen(False)
    catalogue = state / "default.identity-catalog.json"
    assert not catalogue.exists(), "unavailable Keychain published a catalogue"
    print(f"PASS: absent native Keychain fails closed: {unavailable['error']}", flush=True)
    keychain = home / "fixture.keychain-db"
    try:
        # Fresh dscl accounts have no standard user Library directories yet.
        # Provide the normal private locations for user Keychain preferences.
        (home / "Library" / "Preferences").mkdir(parents=True, mode=0o700)
        (home / "Library" / "Keychains").mkdir(mode=0o700)
        security("create-keychain", "-p", password, keychain, password=password)
        security("list-keychains", "-d", "user", "-s", keychain)
        security("default-keychain", "-d", "user", "-s", keychain)
        security("unlock-keychain", "-p", password, keychain, password=password)
        assert is_unlocked(keychain), "fixture Keychain did not unlock"
        assert_native_default(keychain)
        keygen(True, home / "fresh-identity")
        print("PASS: fresh native key generation after Keychain configuration", flush=True)
        keygen(True)
        original = catalogue.read_bytes()
        assert len(json.loads(original)["recipient_keys"]) == 1
        security("lock-keychain", keychain)
        assert not is_unlocked(keychain), "fixture Keychain did not lock"
        public = subprocess.run([str(binary), "tzap", "certs", "--state-dir", str(state), "--json"],
                                capture_output=True, timeout=15)
        assert public.returncode == 0, "public discovery required private Keychain access"
        locked = keygen(False)
        assert catalogue.read_bytes() == original, "locked access changed the existing catalogue"
        print(f"PASS: verified locked Keychain preserves catalogue: {locked['error']}", flush=True)
        security("unlock-keychain", "-p", password, keychain, password=password)
        assert is_unlocked(keychain)
        keygen(True)
        assert len(json.loads(catalogue.read_bytes())["recipient_keys"]) == 2
        print("PASS: native Keychain unlock and key-generation retry", flush=True)
    finally:
        if keychain.exists():
            security("delete-keychain", keychain)


if __name__ == "__main__":
    main()
