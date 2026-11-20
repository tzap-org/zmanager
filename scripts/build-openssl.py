#!/usr/bin/env python3
"""Provision the static OpenSSL used by ZManager's packaging entry points."""

import argparse
import hashlib
import os
from pathlib import Path
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import urlopen


VERSION = "3.5.9"
RELEASE_SHA256 = "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"
RELEASE = f"https://github.com/openssl/openssl/releases/download/openssl-{VERSION}/openssl-{VERSION}.tar.gz"
RSA_PSS_ALIAS_PATCH = "https://github.com/openssl/openssl/commit/af2aaf3271c0b0a193f33d5c0be07754b846759e.patch"
RSA_PSS_ALIAS_PATCH_SHA256 = "e08c7ad5e3f31488eb622515da4434a858038873b07fa1f021271c98bed8e2fe"
RSA_PSS_ALIAS_HEADER = "providers/implementations/include/prov/names.h"
TARGETS = {
    "aarch64-apple-darwin": "darwin64-arm64-cc",
    "x86_64-apple-darwin": "darwin64-x86_64-cc",
    "aarch64-unknown-linux-gnu": "linux-aarch64",
    "x86_64-unknown-linux-gnu": "linux-x86_64",
    "aarch64-unknown-linux-musl": "linux-aarch64",
    "x86_64-unknown-linux-musl": "linux-x86_64",
    "aarch64-pc-windows-msvc": "VC-WIN64-ARM",
    "x86_64-pc-windows-msvc": "VC-WIN64A",
    "aarch64-apple-ios-sim": "iossimulator-arm64-xcrun",
    "x86_64-apple-ios": "iossimulator-x86_64-xcrun",
}


def download_verified(url: str, destination: Path, sha256: str) -> None:
    retryable_statuses = {408, 429, 500, 502, 503, 504}
    attempts = 5
    for attempt in range(attempts):
        digest = hashlib.sha256()
        try:
            with urlopen(url, timeout=60) as response, destination.open("wb") as output:
                while chunk := response.read(1024 * 1024):
                    digest.update(chunk)
                    output.write(chunk)
        except URLError as error:
            if isinstance(error, HTTPError) and error.code not in retryable_statuses:
                raise
            if attempt + 1 == attempts:
                raise
            delay = min(2**attempt, 16) + random.uniform(0, 1)
            print(
                f"Transient download failure for {url}: {error}; "
                f"retrying in {delay:.1f}s ({attempt + 2}/{attempts})",
                file=sys.stderr,
            )
            time.sleep(delay)
            continue
        if digest.hexdigest() != sha256:
            raise ValueError(f"SHA-256 verification failed for {url}")
        return


def native_build(target: str, install: Path, work: Path) -> None:
    archive = work / "openssl.tar.gz"
    patch = work / "openssl-rsa-pss-alias.patch"
    download_verified(RELEASE, archive, RELEASE_SHA256)
    download_verified(RSA_PSS_ALIAS_PATCH, patch, RSA_PSS_ALIAS_PATCH_SHA256)

    env = os.environ.copy()
    target_env = target.replace("-", "_")
    for name in ("CC", "AR", "RANLIB"):
        if compiler := env.get(f"{name}_{target_env}"):
            env[name] = compiler

    subprocess.run(["tar", "-xf", str(archive)], cwd=work, check=True, stdout=sys.stderr)
    source = work / f"openssl-{VERSION}"
    subprocess.run(
        ["git", "apply", f"--include={RSA_PSS_ALIAS_HEADER}", str(patch)],
        cwd=source,
        env={**env, "GIT_CEILING_DIRECTORIES": str(work)},
        check=True,
        stdout=sys.stderr,
    )
    windows = target.endswith("-msvc")
    openssl_dir = "SYS$MANAGER:[OPENSSL]" if windows else "/usr/local/ssl"
    configure = [
        env.get("OPENSSL_SRC_PERL") or env.get("PERL") or "perl",
        "Configure",
        TARGETS[target],
        f"--prefix={install}",
        f"--openssldir={openssl_dir}",
        "--libdir=lib",
        "no-shared",
        "no-module",
        "no-tests",
    ]
    if windows:
        configure += ["no-asm", "no-capieng"]
    if target.endswith("-musl"):
        configure += ["no-engine", "no-async", "-DOPENSSL_NO_SECURE_MEMORY"]

    def run(arguments: list[str]) -> None:
        subprocess.run(arguments, cwd=source, env=env, check=True, stdout=sys.stderr)

    run(configure)
    make = ["nmake"] if windows else ["make", "-j", str(min(os.cpu_count() or 1, 8))]
    run([*make, "build_libs"])
    run([*make, "install_dev"])
    shutil.copyfile(source / "LICENSE.txt", install / "OPENSSL-LICENSE.txt")
    (install / "THIRD-PARTY-NOTICES.txt").write_text(
        f"This ZManager binary statically links OpenSSL {VERSION} (Apache-2.0).\n"
        f"Source: {RELEASE}\n"
        f"Upstream RSA-PSS provider alias diff ({RSA_PSS_ALIAS_HEADER}): {RSA_PSS_ALIAS_PATCH}\n"
        f"Patch SHA-256: {RSA_PSS_ALIAS_PATCH_SHA256}\n"
        "See OPENSSL-LICENSE.txt for the upstream license and notices.\n",
        encoding="utf-8",
    )


def provision(target: str) -> Path:
    root = Path(__file__).resolve().parents[1] / "target" / "zmanager-openssl" / f"{VERSION}-rsa-pss-r1"
    root.mkdir(parents=True, exist_ok=True)
    prefix = root / target
    windows = target.endswith("-msvc")
    libraries = ["libssl.lib", "libcrypto.lib"] if windows else ["libssl.a", "libcrypto.a"]
    version_header = Path("include/openssl/opensslv.h")
    notice = Path("THIRD-PARTY-NOTICES.txt")
    expected = [version_header, Path("OPENSSL-LICENSE.txt"), notice, *(Path("lib") / name for name in libraries)]

    def complete(path: Path) -> bool:
        if not all((path / item).is_file() for item in expected):
            return False
        if RSA_PSS_ALIAS_PATCH_SHA256 not in (path / notice).read_text(encoding="utf-8"):
            return False
        header = (path / version_header).read_text(encoding="utf-8")
        return re.search(rf'^# *define +OPENSSL_VERSION_STR +"{re.escape(VERSION)}"$', header, re.MULTILINE) is not None

    if complete(prefix):
        return prefix
    if prefix.exists():
        if prefix.is_dir() and not prefix.is_symlink():
            shutil.rmtree(prefix)
        else:
            prefix.unlink()
    with tempfile.TemporaryDirectory(dir=root, prefix=f"{target}-") as work_dir:
        work = Path(work_dir)
        install = work / "install"
        native_build(target, install, work)
        if not complete(install):
            raise ValueError("OpenSSL did not install the expected static libraries")
        try:
            install.rename(prefix)
        except OSError:
            if not complete(prefix):
                raise
    return prefix


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=TARGETS)
    args = parser.parse_args()
    try:
        print(provision(args.target))
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"OpenSSL {VERSION} build failed: {error}\n")


if __name__ == "__main__":
    main()
