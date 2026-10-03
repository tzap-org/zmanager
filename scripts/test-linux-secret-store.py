#!/usr/bin/env python3
"""Test a native unlock dialog in a private home, D-Bus session and X server."""
import json
import os
import pathlib
import secrets
import signal
import subprocess
import sys
import tempfile
import time


def run(arguments, **options):
    result = subprocess.run(list(map(str, arguments)), capture_output=True, timeout=30, **options)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    return result.stdout


def dialog(process):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        assert process.poll() is None, "key generation exited before a native unlock dialog appeared"
        result = subprocess.run(["xdotool", "search", "--onlyvisible", "--name", "Unlock.*Keyring"], capture_output=True, timeout=5)
        if result.returncode == 0:
            windows = result.stdout.splitlines()
            assert len(windows) == 1, "expected exactly one fixture unlock dialog"
            return windows[0].decode()
        time.sleep(0.05)
    raise AssertionError("native Secret Service unlock dialog did not appear")


def prompted_keygen(command, authenticate, password):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        window = dialog(process)
        run(["xdotool", "windowfocus", window])
        if authenticate:
            # Only the random disposable keyring password enters this X server.
            run(["xdotool", "type", "--clearmodifiers", "--file", "-"], input=password)
            run(["xdotool", "key", "Return"])
        else:
            run(["xdotool", "key", "Escape"])
        output, errors = process.communicate(timeout=15)
        assert process.returncode == 0 if authenticate else process.returncode != 0, errors.decode(errors="replace")
        assert password not in output + errors, "fixture keyring password was echoed"
        return json.loads(output)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)
        process.stdout.close()
        process.stderr.close()


def exercise(binary, password):
    state = pathlib.Path(os.environ["HOME"]) / "identity"
    command = [str(binary), "tzap", "contact", "keygen", "--state-dir", str(state), "--json"]
    assert json.loads(run(command))["generated"] is True
    catalog = state / "default.identity-catalog.json"
    original = catalog.read_bytes()
    unavailable_environment = os.environ.copy()
    unavailable_environment["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={state / 'absent-bus'}"
    unavailable = subprocess.run(command, env=unavailable_environment, capture_output=True, timeout=15)
    assert unavailable.returncode != 0
    assert "secure secret store is unavailable" in json.loads(unavailable.stdout)["error"]
    assert catalog.read_bytes() == original, "unavailable keyring changed the catalogue"
    print("PASS: unavailable native service preserves existing identity state", flush=True)
    service = ["gdbus", "call", "--session", "--dest", "org.freedesktop.secrets", "--object-path", "/org/freedesktop/secrets", "--method"]
    collection = "/org/freedesktop/secrets/collection/login"
    assert collection.encode() in run(service + ["org.freedesktop.Secret.Service.Lock", f"['{collection}']"])
    properties = ["gdbus", "call", "--session", "--dest", "org.freedesktop.secrets", "--object-path", collection, "--method", "org.freedesktop.DBus.Properties.Get", "org.freedesktop.Secret.Collection"]
    assert b"true" in run(properties + ["Locked"]), "fixture collection was not locked"
    items = run(properties + ["Items"])
    run([binary, "tzap", "certs", "--state-dir", state, "--json"])
    denied = prompted_keygen(command, False, password)
    assert denied["ok"] is False and "secure secret store is locked" in denied["error"]
    assert catalog.read_bytes() == original, "cancelled authentication changed the catalogue"
    assert run(properties + ["Items"]) == items, "cancelled key generation left a native secret"
    print("PASS: locked native keyring, public discovery and cancelled unlock preserve state", flush=True)
    assert prompted_keygen(command, True, password)["generated"] is True
    assert b"false" in run(properties + ["Locked"])
    assert len(json.loads(catalog.read_bytes())["recipient_keys"]) == 2
    print("PASS: native unlock authentication and key-generation recovery", flush=True)


def isolated(binary):
    password = secrets.token_hex(24).encode()
    daemon = subprocess.Popen(["gnome-keyring-daemon", "--foreground", "--login"], stdin=subprocess.PIPE,
                              stdout=subprocess.DEVNULL)
    try:
        daemon.stdin.write(password)
        daemon.stdin.close()
        deadline = time.monotonic() + 10
        control = pathlib.Path(os.environ["XDG_RUNTIME_DIR"]) / "keyring" / "control"
        while not control.exists():
            assert daemon.poll() is None and time.monotonic() < deadline, "fixture keyring daemon did not start"
            time.sleep(0.05)
        run(["gnome-keyring-daemon", "--start", "--components=secrets"])
        exercise(binary, password)
    finally:
        # This PID belongs to the private bus, not the caller's desktop session.
        try:
            prompter = subprocess.run(["gdbus", "call", "--session", "--dest", "org.freedesktop.DBus", "--object-path",
                                      "/org/freedesktop/DBus", "--method", "org.freedesktop.DBus.GetConnectionUnixProcessID",
                                      "org.gnome.keyring.SystemPrompter"], capture_output=True, timeout=5)
            if prompter.returncode == 0:
                pid = int(prompter.stdout.decode().split("uint32 ")[1].split(",")[0])
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        finally:
            daemon.terminate()
            daemon.wait(timeout=10)


def main():
    assert sys.platform == "linux", "Linux Secret Service required"
    binary = pathlib.Path(sys.argv[1]).resolve(strict=True)
    if sys.argv[2:] == ["--isolated"]:
        isolated(binary)
        return
    with tempfile.TemporaryDirectory(prefix="zm-private-keyring-") as directory:
        root = pathlib.Path(directory)
        (root / "run").mkdir(mode=0o700)
        environment = os.environ.copy()
        environment.update(HOME=str(root), XDG_DATA_HOME=str(root / "data"), XDG_CACHE_HOME=str(root / "cache"),
                           XDG_RUNTIME_DIR=str(root / "run"), LANG="C.UTF-8", LC_ALL="C.UTF-8")
        for name in ("DBUS_SESSION_BUS_ADDRESS", "GNOME_KEYRING_CONTROL", "DISPLAY", "WAYLAND_DISPLAY", "SESSION_MANAGER"):
            environment.pop(name, None)
        # The bus starts after setting HOME: auto-activated daemons inherit only
        # the fixture environment, never the caller's personal keyring location.
        subprocess.run(["xvfb-run", "-a", "dbus-run-session", "--", sys.executable, str(pathlib.Path(__file__).resolve()),
                        str(binary), "--isolated"], env=environment, check=True, timeout=90)


if __name__ == "__main__":
    main()
