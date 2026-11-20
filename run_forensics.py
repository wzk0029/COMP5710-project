"""
run_forensics.py - runs the forensics-instrumented SLI-KUBE methods and produces the forensics log.

Usage:
    python run_forensics.py [directory] [--max-files N]

    directory    folder containing YAML manifests (default: TEST_ARTIFACTS)
    --max-files  analyse at most N files, sorted by path (default: 10)

Outputs
    forensics.log                 one line per CALL / RETURN / EXCEPTION / EVENT
    forensics_logs/summary.md     per-method counts, built from forensics.log

Exit code
    0  every one of the 10 instrumented methods was called at least once
    1  no YAML files found, or at least one instrumented method was never called
Exceptions raised *inside* the methods are evidence, not failures: they are captured in
the log and the run continues.
"""
import argparse
import collections
import os
import platform
import sys

os.environ.pop("FORENSICS_DISABLED", None)   # CI disables logging for other steps; we want it on here

import forensics   # noqa: E402
import parser      # noqa: E402  (the project's own parser.py)
import scanner     # noqa: E402

LOG_FILE = os.environ.get("FORENSICS_LOG", forensics.DEFAULT_LOG)
SUMMARY_DIR = "forensics_logs"

TARGETS = [
    "parser.checkIfWeirdYAML",
    "parser.checkParseError",
    "parser.loadMultiYAML",
    "parser.checkIfValidK8SYaml",
    "parser.getSingleDict4MultiDocs",
    "scanner.getYAMLFiles",
    "scanner.checkIfValidSecret",
    "scanner.scanForSecrets",
    "scanner.scanForTruePID",
    "scanner.scanForDefaultNamespace",
]

# Synthetic values for checkIfValidSecret: empty, tiny, normal, padded/mixed case, wrong types.
SAMPLE_VALUES = ["", "x", "demo-value-123", "  MixedCase99  ", None, 42]


def attempt(label, func, *args):
    """Call func; if it raises, the decorator has already logged it, so just note it and go on."""
    try:
        return True, func(*args)
    except Exception as exc:
        print("  [captured %s in %s]" % (type(exc).__name__, label))
        return False, None


def summarise_log(log_file):
    counts = collections.defaultdict(lambda: collections.Counter())
    with open(log_file, encoding="utf-8") as handle:
        for line in handle:
            parts = line.rstrip("\n").split(" | ", 4)
            if len(parts) == 5:
                counts[parts[2]][parts[3]] += 1
    return counts


def write_summary(counts):
    os.makedirs(SUMMARY_DIR, exist_ok=True)
    lines = ["## Forensics summary", "",
             "| Method | CALL | RETURN | EXCEPTION | EVENT |", "|---|---|---|---|---|"]
    for name in TARGETS:
        c = counts.get(name, {})
        lines.append("| %s | %d | %d | %d | %d |"
                     % (name, c.get("CALL", 0), c.get("RETURN", 0), c.get("EXCEPTION", 0), c.get("EVENT", 0)))
    text = "\n".join(lines) + "\n"
    with open(os.path.join(SUMMARY_DIR, "summary.md"), "w", encoding="utf-8") as handle:
        handle.write(text)
    return text


def main():
    ap = argparse.ArgumentParser(description="Run forensics-instrumented SLI-KUBE methods.")
    ap.add_argument("directory", nargs="?", default="TEST_ARTIFACTS")
    ap.add_argument("--max-files", type=int, default=10)
    args = ap.parse_args()

    forensics.reset_log()
    forensics.event("RUN_START python=%s os=%s dir=%s github_run_id=%s github_sha=%s" % (
        platform.python_version(), platform.system(), forensics.path(args.directory),
        os.environ.get("GITHUB_RUN_ID", "local"), os.environ.get("GITHUB_SHA", "local")))

    files = sorted(scanner.getYAMLFiles(args.directory))
    if not files:
        print("No YAML files found under %s" % args.directory)
        return 1
    files = files[:args.max_files]
    print("Analysing %d YAML file(s) from %s" % (len(files), args.directory))

    for yml in files:
        print("-", yml)
        attempt("checkIfWeirdYAML", parser.checkIfWeirdYAML, yml)
        attempt("checkParseError", parser.checkParseError, yml)
        attempt("checkIfValidK8SYaml", parser.checkIfValidK8SYaml, yml)
        ok, docs = attempt("loadMultiYAML", parser.loadMultiYAML, yml)
        if ok:
            ok, merged = attempt("getSingleDict4MultiDocs", parser.getSingleDict4MultiDocs, docs)
            if ok:
                attempt("scanForSecrets", scanner.scanForSecrets, merged)
        attempt("scanForTruePID", scanner.scanForTruePID, yml)
        attempt("scanForDefaultNamespace", scanner.scanForDefaultNamespace, yml)

    for value in SAMPLE_VALUES:
        attempt("checkIfValidSecret", scanner.checkIfValidSecret, value)

    forensics.event("RUN_END files=%d" % len(files))

    counts = summarise_log(LOG_FILE)
    print()
    print(write_summary(counts))
    missing = [t for t in TARGETS if counts.get(t, {}).get("CALL", 0) == 0]
    if missing:
        print("ERROR: instrumented methods never called: %s" % ", ".join(missing))
        return 1
    print("OK: all %d instrumented methods were exercised. Log: %s" % (len(TARGETS), LOG_FILE))
    return 0


if __name__ == "__main__":
    sys.exit(main())
