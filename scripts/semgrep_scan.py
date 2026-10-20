#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Run the local semgrep scan configured by the repository-root semgrep.toml.

Semgrep (v1.180.0, OSS) does not read TOML, and its in-config ``extends`` /
``exclude-rules`` keys are inert in this version (verified to load 0 rules /
not filter). This script is therefore the translation layer: it reads the TOML
and builds a ``semgrep scan`` invocation from the mechanisms that are proven to
work - one ``--config`` per ruleset, one ``--exclude-rule`` per deactivation,
plus the repository ``.semgrepignore`` which semgrep applies automatically.

Usage (from the repository root):
    python scripts/semgrep_scan.py                 # human-readable report
    python scripts/semgrep_scan.py --json          # machine-readable results
    python scripts/semgrep_scan.py --sync-rules    # clone third-party rule repos first
    python scripts/semgrep_scan.py --dry-run       # print the command, run nothing
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TOML_PATH = REPO_ROOT / "semgrep.toml"
RULES_CACHE = REPO_ROOT / ".semgrep_cache"


def load_config() -> dict:
    """Read and parse the repository-root semgrep.toml."""
    if not TOML_PATH.is_file():
        sys.exit(f"error: {TOML_PATH} not found; run from the repository root")
    with open(TOML_PATH, "rb") as f:
        return tomllib.load(f)


def slugify(url: str) -> str:
    """Repo directory name for a third-party rules URL (owner-repo)."""
    url = url.rstrip("/").removesuffix(".git")
    parts = [p for p in url.split("/") if p and not p.startswith(("http", "https"))]
    # keep only the last two path segments: owner/repo
    tail = parts[-2:] if len(parts) >= 2 else parts
    return "-".join(re.sub(r"[^A-Za-z0-9._-]", "-", t) for t in tail)


def expanded_exclude_ids(short_id: str, rule_dirs: list[Path]) -> list[str]:
    """Return the bare rule id plus the path-prefixed ids of directory-loaded rules.

    When semgrep loads rules from a directory it prefixes rule ids with the
    dot-separated config path, so the bare id no longer matches --exclude-rule
    (verified on semgrep 1.180.0). Unmatched ids are tolerated by semgrep, so
    every form is emitted and the matching one takes effect.
    """
    ids = [short_id]
    for rules_dir in rule_dirs:
        rel_config = rules_dir.relative_to(REPO_ROOT).as_posix().lstrip("./")
        config_part = rel_config.replace("/", ".")
        for rule_file in sorted(rules_dir.rglob("*.y*ml")):
            try:
                text = rule_file.read_text(errors="ignore")
            except OSError:
                continue
            # id lines appear both as top-level (`id:`) and as list items (`- id:`)
            if re.search(rf"(?m)^[ \t]*-?[ \t]*id:[ \t]*[\"']?{re.escape(short_id)}[\"']?[ \t]*(#.*)?$", text):
                parent = rule_file.parent.relative_to(rules_dir).as_posix()
                parent_part = "" if parent == "." else parent.replace("/", ".")
                full_id = ".".join(p for p in (config_part, parent_part, short_id) if p)
                if full_id not in ids:
                    ids.append(full_id)
    return ids


def sync_rules(urls: list[str], json_mode: bool = False) -> list[Path]:
    """Shallow-clone third-party rule repositories and prune non-rule YAML.

    Semgrep parses every .yaml/.yml under a --config directory as a rule file;
    rule repos ship their own CI configs, and a single malformed file aborts
    the whole scan (exit 7). A real rule file has a top-level ``rules:`` key.
    """
    info = (lambda msg: print(msg, file=sys.stderr)) if json_mode else print
    found: list[Path] = []
    RULES_CACHE.mkdir(exist_ok=True)
    for url in urls:
        dest = RULES_CACHE / slugify(url)
        if dest.is_dir():
            info(f"  using existing clone: {dest}")
        else:
            info(f"  cloning {url} -> {dest}")
            r = subprocess.run(["git", "clone", "--depth", "1", url, str(dest)], capture_output=True, text=True)
            if r.returncode != 0:
                info(f"  WARNING: clone failed: {r.stderr.strip().splitlines()[-1] if r.stderr else 'unknown'}")
                continue
        pruned = 0
        for yml in list(dest.rglob("*.yaml")) + list(dest.rglob("*.yml")):
            try:
                first_line = yml.read_text(errors="ignore").lstrip().splitlines()[0]
            except (IndexError, OSError):
                first_line = ""
            if not first_line.startswith("rules:"):
                yml.unlink()
                pruned += 1
        info(f"  pruned {pruned} non-rule YAML file(s)")
        found.append(dest)
    return found


def build_command(cfg: dict, json_out: bool, rule_dirs: list[Path]) -> list[str]:
    """Build the semgrep command from the TOML config (rulesets, excludes, targets)."""
    scan = cfg["scan"]
    cmd = [
        "semgrep", "scan",
        f"--metrics={scan.get('metrics', 'off')}",
        "--max-target-bytes", "20000000",
    ]
    for ruleset in scan["rulesets"]:
        cmd += ["--config", ruleset]
    for rules_dir in rule_dirs:
        cmd += ["--config", str(rules_dir.relative_to(REPO_ROOT))]
    for exc in cfg.get("exclude", []):
        if exc.get("id"):
            for rule_id in expanded_exclude_ids(exc["id"], rule_dirs):
                cmd += ["--exclude-rule", rule_id]
    if json_out:
        cmd += ["--json"]
    for target in scan["targets"]:
        t = REPO_ROOT / target
        if not t.is_dir():
            sys.exit(f"error: scan target does not exist: {t}")
        cmd.append(str(t.relative_to(REPO_ROOT)))
    return cmd


def main() -> int:
    """CLI entry point: parse arguments, build and run the semgrep scan."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--dry-run", action="store_true", help="print the command and exit")
    parser.add_argument("--sync-rules", action="store_true", help="clone/update third-party rule repos first")
    args = parser.parse_args()

    if os.environ.get("SEMGREP_METRICS_OVERRIDE"):
        print("warning: SEMGREP_METRICS_OVERRIDE is set; local scans must keep --metrics=off", file=sys.stderr)

    cfg = load_config()
    third_party = cfg["scan"].get("third_party", []) or []
    rule_dirs: list[Path] = []

    if args.sync_rules:
        if not third_party:
            print("nothing to sync: third_party is empty in semgrep.toml")
        else:
            print(f"syncing {len(third_party)} third-party rule repo(s) into {RULES_CACHE.relative_to(REPO_ROOT)}/",
                  file=sys.stderr if args.json else sys.stdout)
            rule_dirs = sync_rules(third_party, json_mode=args.json)
    elif third_party:
        # Not explicitly syncing: use whatever clones already exist, warn about missing ones.
        for url in third_party:
            dest = RULES_CACHE / slugify(url)
            if dest.is_dir():
                rule_dirs.append(dest)
            else:
                print(f"warning: {url} not cloned; run with --sync-rules to include it", file=sys.stderr)

    cmd = build_command(cfg, args.json, rule_dirs)
    if args.dry_run:
        print(" ".join(cmd))
        return 0

    active_excludes = [e["id"] for e in cfg.get("exclude", []) if e.get("id")]
    if active_excludes:
        print(f"deactivated rule(s) from semgrep.toml: {', '.join(active_excludes)}",
              file=sys.stderr if args.json else sys.stdout)

    print(f"scanning: {', '.join(cfg['scan']['targets'])} (rulesets: {', '.join(cfg['scan']['rulesets'])})",
          file=sys.stderr if args.json else sys.stdout)
    r = subprocess.run(cmd, cwd=REPO_ROOT)
    # semgrep exits 1 when it found blocking findings, and 2 (plain mode) / 0
    # (JSON mode, observed on v1.180.0) when some rules of the loaded configs
    # failed to compile while the rest ran. Both are successful scans; the
    # reliable finding count is in the JSON output, not the exit code.
    # Anything else is an error.
    allowed = (0, 1, 2)
    if r.returncode not in allowed:
        print(f"error: semgrep exited with {r.returncode}", file=sys.stderr)
        return r.returncode
    if r.returncode == 2:
        print("note: some rules failed to compile; results are partial.", file=sys.stderr)
    if not args.json:
        print()
        print("note: semgrep exit code 1 = findings present (scan itself succeeded).")
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
