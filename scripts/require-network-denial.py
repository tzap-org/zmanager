#!/usr/bin/env python3
"""Prove network denial in the current sandbox, then execute an offline suite.

macOS invokes this inside sandbox-exec; Linux invokes it in a network namespace
with no external interface. This script does not change the host's network.
"""
import errno
import os
import socket
import sys


def main():
    if sys.platform == "linux":
        interfaces = {name for _, name in socket.if_nameindex()}
        assert interfaces <= {"lo"}, f"external network interface is still present: {interfaces}"
    elif sys.platform != "darwin":
        raise SystemExit("This network-denial probe supports macOS and Linux only.")
    try:
        with socket.socket() as connection:
            connection.settimeout(3)
            # RFC 5737 documentation address. No DNS or live service is needed.
            connection.connect(("192.0.2.1", 443))
    except OSError as error:
        expected = {errno.EPERM, errno.EACCES} if sys.platform == "darwin" else {errno.ENETUNREACH, errno.EHOSTUNREACH}
        assert error.errno in expected, f"network denial was not proved: {error}"
    else:
        raise AssertionError("outbound TCP succeeded inside the offline test sandbox")
    print(f"PASS: outbound TCP denied on {sys.platform}", flush=True)
    assert len(sys.argv) > 1, "an offline test command is required"
    # Compiler cache daemons can use local TCP. The test sandbox must keep that
    # denied too, so compile directly if Cargo needs to refresh a test binary.
    os.environ["RUSTC_WRAPPER"] = ""
    os.environ["RUSTC_WORKSPACE_WRAPPER"] = ""
    os.execvp(sys.argv[1], sys.argv[1:])


if __name__ == "__main__":
    main()
