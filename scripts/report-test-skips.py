#!/usr/bin/env python3
"""Summarize actual optional-test skip events captured by Rust test helpers."""
import collections
import json
import os
import pathlib
import sys


def summary(path):
    counts = collections.Counter()
    for line in path.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        counts[(record["test"], record["reason"], record["file"], record["line"])] += 1
    rows = ["### Optional test checks skipped", "",
            "These checks returned early; passing Cargo totals do not include their validation.", ""]
    if counts:
        rows += ["| Check | Reason | Location | Occurrences |", "| --- | --- | --- | --- |"]
        for (test, reason, source, line), count in sorted(counts.items()):
            cells = [test, reason, f"{source}:{line}", str(count)]
            rows.append("| " + " | ".join(cell.replace("|", "\\|").replace("\n", " ") for cell in cells) + " |")
    else:
        rows.append("No skip events were recorded by instrumented tests. This does not establish that every test ran.")
    return "\n".join(rows) + "\n"


def main():
    path = pathlib.Path(sys.argv[1])
    output = summary(path)
    print(output)
    if destination := os.environ.get("GITHUB_STEP_SUMMARY"):
        with pathlib.Path(destination).open("a", encoding="utf-8") as report:
            report.write(output)


if __name__ == "__main__":
    main()
