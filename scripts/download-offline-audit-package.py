#!/usr/bin/env python3
"""Download an offline package only after its exact producer job succeeded."""
import argparse
import json
import pathlib
import re
import subprocess

TARGETS = (
    "aarch64-apple-darwin", "x86_64-apple-darwin",
    "aarch64-unknown-linux-musl", "x86_64-unknown-linux-musl",
    "aarch64-pc-windows-msvc", "x86_64-pc-windows-msvc",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--target", required=True, choices=TARGETS)
    parser.add_argument("--destination", required=True, type=pathlib.Path)
    arguments = parser.parse_args()
    assert arguments.run_id > 0 and re.fullmatch(r"[0-9a-f]{40}", arguments.commit), "invalid package build identity"
    run = json.loads(subprocess.check_output([
        "gh", "run", "view", str(arguments.run_id), "--json", "headSha,workflowName,jobs",
    ]))
    assert run["workflowName"] == "Package Preview" and run["headSha"] == arguments.commit, "package workflow or commit mismatch"
    jobs = [job for job in run["jobs"] if job["name"] == arguments.target]
    assert len(jobs) == 1 and jobs[0]["status"] == "completed" and jobs[0]["conclusion"] == "success", "selected package producer has not succeeded"
    subprocess.run([
        "gh", "run", "download", str(arguments.run_id), "--name",
        f"zm-preview-{arguments.target}-offline", "--dir", str(arguments.destination),
    ], check=True)
    print(f"PASS: downloaded {arguments.target} from successful producer job {jobs[0]['databaseId']} at {arguments.commit}", flush=True)


if __name__ == "__main__":
    main()
