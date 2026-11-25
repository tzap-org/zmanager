#!/usr/bin/env python3
"""Publish draft CLI releases only after Apple notarization and Gatekeeper pass."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request


API = "https://api.github.com"
REPOSITORY = os.environ["GITHUB_REPOSITORY"]
TOKEN = os.environ["GH_TOKEN"]
API_HEADERS = {
    "Accept": "application/vnd.github+json",
    "Authorization": f"Bearer {TOKEN}",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "zmanager-notarization-release-poller",
}
APPLE_KEY = os.environ["APPLE_API_KEY_PATH"]
APPLE_KEY_ID = os.environ["APPLE_API_KEY_ID"]
APPLE_ISSUER = os.environ["APPLE_API_ISSUER_ID"]
ONLY_TAG = os.environ.get("RELEASE_TAG", "").strip()


def api_json(url: str, method: str = "GET", payload: dict | None = None) -> dict | list:
    data = json.dumps(payload).encode() if payload is not None else None
    headers = dict(API_HEADERS)
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=60) as response:
        body = response.read()
    return json.loads(body) if body else {}


def download_asset(asset: dict, destination: pathlib.Path) -> None:
    request = urllib.request.Request(
        asset["url"],
        headers={**API_HEADERS, "Accept": "application/octet-stream"},
    )
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, file_pointer, code, message, headers, new_url):
            return None

    no_redirect = urllib.request.build_opener(NoRedirect())
    try:
        with no_redirect.open(request, timeout=120) as response:
            destination.write_bytes(response.read())
    except urllib.error.HTTPError as response:
        if response.code not in {301, 302, 303, 307, 308}:
            raise
        location = response.headers.get("Location")
        if not location:
            raise RuntimeError(f"GitHub returned a redirect without a location for {asset['name']}")
        # GitHub's signed asset URL is self-authenticating; do not forward the
        # repository token to the redirected host.
        redirected = urllib.request.Request(location, headers={"User-Agent": API_HEADERS["User-Agent"]})
        with urllib.request.urlopen(redirected, timeout=120) as download:
            destination.write_bytes(download.read())


def list_draft_releases() -> list[dict]:
    url = f"{API}/repos/{REPOSITORY}/releases?per_page=100"
    releases: list[dict] = []
    while url:
        request = urllib.request.Request(url, headers=API_HEADERS)
        with urllib.request.urlopen(request, timeout=60) as response:
            releases.extend(item for item in json.loads(response.read()) if item["draft"])
            link = response.headers.get("Link", "")
        next_url = ""
        for part in link.split(","):
            if 'rel="next"' in part:
                next_url = part[part.find("<") + 1 : part.find(">")]
                break
        url = next_url
    return releases


def notary_info(submission_id: str) -> dict:
    result = subprocess.run(
        [
            "xcrun", "notarytool", "info", submission_id,
            "--key", APPLE_KEY, "--key-id", APPLE_KEY_ID,
            "--issuer", APPLE_ISSUER, "--output-format", "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def print_notary_log(submission_id: str) -> None:
    result = subprocess.run(
        [
            "xcrun", "notarytool", "log", submission_id,
            "--key", APPLE_KEY, "--key-id", APPLE_KEY_ID,
            "--issuer", APPLE_ISSUER, "--output-format", "json",
        ],
        capture_output=True,
        text=True,
    )
    print(result.stdout or result.stderr)


def verify_archive(archive: pathlib.Path, binary_name: str, expected_cdhash: str, work: pathlib.Path) -> pathlib.Path:
    with tarfile.open(archive, "r:gz") as package:
        member = next((item for item in package.getmembers() if item.name == binary_name), None)
        if member is None or not member.isfile():
            raise RuntimeError(f"{archive.name} does not contain the expected {binary_name} executable")
        stream = package.extractfile(member)
        if stream is None:
            raise RuntimeError(f"Could not read {binary_name} from {archive.name}")
        binary = work / f"{archive.name}.{binary_name}"
        binary.write_bytes(stream.read())
    binary.chmod(0o755)
    subprocess.run(["codesign", "--verify", "--strict", "--verbose=2", str(binary)], check=True)
    details = subprocess.run(
        ["codesign", "-dv", "--verbose=4", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )
    actual_cdhash = next(
        (line.partition("=")[2].strip() for line in details.stderr.splitlines() if line.startswith("CDHash=")),
        "",
    )
    if actual_cdhash.lower() != expected_cdhash.lower():
        raise RuntimeError(f"Code directory hash mismatch for {archive.name}")
    quarantine = f"0081;{int(time.time()):x};GitHub Actions;"
    subprocess.run(["xattr", "-w", "com.apple.quarantine", quarantine, str(binary)], check=True)
    assessment = subprocess.run(
        ["spctl", "--assess", "--type", "execute", "--verbose=4", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )
    if assessment.returncode:
        raise RuntimeError(
            f"Gatekeeper has not accepted {archive.name}: "
            f"{assessment.stderr.strip() or assessment.stdout.strip()}"
        )
    print(f"Gatekeeper accepted {archive.name}: {assessment.stderr.strip() or assessment.stdout.strip()}")
    return binary


def process_release(release: dict) -> bool:
    tag = release["tag_name"]
    assets = {asset["name"]: asset for asset in release.get("assets", [])}
    manifest_asset = assets.get("notarization-submissions.json")
    if not manifest_asset:
        return False
    print(f"Checking draft {tag}")

    with tempfile.TemporaryDirectory(prefix="zmanager-notary-") as temporary:
        work = pathlib.Path(temporary)
        manifest_path = work / "notarization-submissions.json"
        download_asset(manifest_asset, manifest_path)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("schema_version") != 2 or manifest.get("tag") != tag:
            raise RuntimeError(f"Invalid notarization manifest for {tag}")
        submissions = manifest.get("submissions", [])
        expected_targets = {"aarch64-apple-darwin", "x86_64-apple-darwin"}
        expected_archives = {
            (target, f"zm-{target}.tar.gz") for target in expected_targets
        } | {
            (target, f"zm-full-{target}.tar.gz") for target in expected_targets
        }
        actual_archives = {(record.get("target"), record.get("archive")) for record in submissions}
        if actual_archives != expected_archives or len(submissions) != 4:
            raise RuntimeError(f"Draft {tag} is missing a per-binary notarization submission")

        statuses: list[tuple[str, str]] = []
        for record in submissions:
            submission_id = record["submission_id"]
            info = notary_info(submission_id)
            status = info.get("status", "Unknown")
            print(f"{record['target']} {record['binary']} {submission_id}: {status}")
            statuses.append((submission_id, status))
            if status == "Invalid":
                print(f"Apple rejection log for {submission_id}:")
                print_notary_log(submission_id)
        if any(status != "Accepted" for _, status in statuses):
            print(f"Apple is still processing or rejected at least one submission for {tag}; draft remains unpublished.")
            return False

        sums_asset = assets.get("SHA256SUMS")
        if not sums_asset:
            raise RuntimeError(f"Draft {tag} has no SHA256SUMS asset")
        sums_path = work / "SHA256SUMS"
        download_asset(sums_asset, sums_path)
        expected_hashes: dict[str, str] = {}
        for line in sums_path.read_text(encoding="utf-8").splitlines():
            checksum, separator, name = line.partition("  ")
            if separator:
                expected_hashes[name.strip()] = checksum

        for record in submissions:
            archive_name = record["archive"]
            asset = assets.get(archive_name)
            if not asset:
                raise RuntimeError(f"Draft {tag} is missing {archive_name}")
            archive = work / archive_name
            download_asset(asset, archive)
            expected_hash = expected_hashes.get(archive_name)
            if not expected_hash or hashlib.sha256(archive.read_bytes()).hexdigest() != expected_hash:
                raise RuntimeError(f"Checksum verification failed for {archive_name}")
            verify_archive(archive, record["binary"], record["cdhash"], work)

    release_url = f"{API}/repos/{REPOSITORY}/releases/{release['id']}"
    api_json(release_url, method="PATCH", payload={"draft": False})
    print(f"Published {tag} after Apple acceptance and Gatekeeper verification.")
    try:
        api_json(f"{API}/repos/{REPOSITORY}/releases/assets/{manifest_asset['id']}", method="DELETE")
        print("Removed the private notarization manifest from the published release.")
    except urllib.error.HTTPError as error:
        print(f"::warning::Published {tag}, but could not remove the notarization manifest: HTTP {error.code}")
    return True


def main() -> int:
    releases = list_draft_releases()
    if ONLY_TAG:
        releases = [release for release in releases if release["tag_name"] == ONLY_TAG]
    eligible = [
        release for release in releases
        if any(asset["name"] == "notarization-submissions.json" for asset in release.get("assets", []))
    ]
    if not eligible:
        print(f"No notarization draft releases found{f' for {ONLY_TAG}' if ONLY_TAG else ''}.")
        return 0
    for release in eligible:
        process_release(release)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (urllib.error.URLError, subprocess.CalledProcessError, json.JSONDecodeError, KeyError, RuntimeError) as error:
        print(f"::error::{error}", file=sys.stderr)
        raise SystemExit(1)
