#!/usr/bin/env python3
"""Verify FieldNet Kit (fnkit) dependencies from dependencies.manifest.json (all platforms)."""

from __future__ import annotations

import argparse
import importlib.util
import json
import platform
import shutil
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "dependencies.manifest.json"


def detect_os() -> str:
    s = platform.system().lower()
    if s == "darwin":
        return "macos"
    if s == "windows":
        return "windows"
    return "linux"


def load_manifest() -> Dict[str, Any]:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _cli_found(bins: List[str]) -> Optional[str]:
    for b in bins:
        if shutil.which(b):
            return b
    return None


def _check_nettacker() -> Tuple[bool, str]:
    if shutil.which("nettacker"):
        return True, "nettacker"
    for p in (
        REPO_ROOT / "Nettacker" / "nettacker.py",
        Path.home() / "Nettacker" / "nettacker.py",
    ):
        if p.is_file():
            return True, str(p)
    return False, ""


def check_one(dep: Dict[str, Any], *, os_id: str) -> Tuple[str, str, str]:
    """Return (status, detail, scope) where status is ok|missing|skip|warn."""
    scope = dep.get("scope", "optional")
    check = dep.get("check") or {}
    kind = check.get("kind", "cli")

    if dep.get("platforms") and os_id not in dep["platforms"]:
        return "skip", "not applicable on this OS", scope

    if kind == "python_version":
        min_ver = check.get("min", "3.10")
        need = tuple(int(x) for x in min_ver.split(".")[:2])
        cur = sys.version_info[:2]
        if cur >= need:
            return "ok", f"Python {sys.version.split()[0]}", scope
        return "missing", f"need >={min_ver}, have {sys.version.split()[0]}", scope

    if kind == "cli":
        found = _cli_found(check.get("bins", []))
        if found:
            return "ok", found, scope
        return "missing", "not in PATH", scope

    if kind == "cli_any":
        found = _cli_found(check.get("bins", []))
        if found:
            return "ok", found, scope
        return "missing", "none of: " + ", ".join(check.get("bins", [])), scope

    if kind == "pip":
        mod = check.get("import", "")
        if mod and importlib.util.find_spec(mod):
            return "ok", f"import {mod}", scope
        req = check.get("requirements", "")
        hint = f"pip install -r {req}" if req else "pip install package"
        return "missing", hint, scope

    if kind == "nettacker":
        ok, path = _check_nettacker()
        if ok:
            return "ok", path, scope
        return "missing", "install Nettacker (AGPL) — see docs/OWASP_THIRD_PARTY.md", scope

    if kind == "network":
        url = check.get("url", "")
        try:
            req = urllib.request.Request(url, method="GET", headers={"User-Agent": "fnkit-check-deps/1.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                if 200 <= resp.status < 500:
                    return "ok", f"HTTP {resp.status}", scope
        except urllib.error.HTTPError as exc:
            if exc.code < 500:
                return "ok", f"HTTP {exc.code}", scope
            return "warn", str(exc), scope
        except Exception as exc:
            return "warn", str(exc), scope
        return "warn", "no response", scope

    if kind in ("note",):
        return "ok", check.get("message", "n/a"), scope

    return "warn", f"unknown check kind {kind}", scope


def deps_for_groups(manifest: Dict[str, Any], groups: List[str]) -> List[Dict[str, Any]]:
    all_deps = manifest["dependencies"]
    if "all" in groups:
        return all_deps
    ids: set[str] = set()
    fg = manifest.get("feature_groups", {})
    for g in groups:
        if g == "minimal":
            ids.update(fg.get("core", []))
        elif g == "full":
            for lst in fg.values():
                ids.update(lst)
        elif g in fg:
            ids.update(fg[g])
    if not ids:
        return all_deps
    return [d for d in all_deps if d["id"] in ids]


def run_check(
    *,
    groups: List[str],
    json_out: bool = False,
    fail_on_required: bool = True,
) -> int:
    manifest = load_manifest()
    os_id = detect_os()
    deps = deps_for_groups(manifest, groups)
    rows: List[Dict[str, str]] = []
    missing_required = 0

    for dep in deps:
        status, detail, scope = check_one(dep, os_id=os_id)
        rows.append(
            {
                "id": dep["id"],
                "name": dep.get("name", dep["id"]),
                "scope": scope,
                "status": status,
                "detail": detail,
                "type": dep.get("type", ""),
                "feature_group": dep.get("feature_group", ""),
            }
        )
        if status == "missing" and scope == "required":
            missing_required += 1

    if json_out:
        print(json.dumps({"os": os_id, "groups": groups, "results": rows}, indent=2, ensure_ascii=False))
    else:
        print(f"FieldNet Kit (fnkit) dependencies (OS: {os_id}, groups: {', '.join(groups)})\n")
        print(f"{'ID':<22} {'SCOPE':<10} {'STATUS':<8} DETAIL")
        print("-" * 72)
        for r in rows:
            if r["status"] == "skip":
                continue
            mark = r["status"].upper()
            print(f"{r['id']:<22} {r['scope']:<10} {mark:<8} {r['detail']}")

    if fail_on_required and missing_required:
        if not json_out:
            print(f"\nMissing {missing_required} required dependency(ies).")
        return 1
    return 0


def install_hints(manifest: Dict[str, Any], groups: List[str]) -> None:
    os_id = detect_os()
    print(f"Install hints for {os_id} (groups: {', '.join(groups)}):\n")
    for dep in deps_for_groups(manifest, groups):
        inst = dep.get("install") or {}
        block = inst.get(os_id) or inst.get("all") or {}
        if not block:
            continue
        print(f"  [{dep['id']}]")
        for k, v in block.items():
            if isinstance(v, list):
                print(f"    {k}: {' '.join(str(x) for x in v)}")
            else:
                print(f"    {k}: {v}")
        print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Check FieldNet Kit (fnkit) external dependencies")
    parser.add_argument(
        "--group",
        action="append",
        dest="groups",
        default=None,
        help="Feature group: minimal, core, diagnostics, scan, pcap, dns, enrichment, owasp, speedtest, full, all",
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--hints", action="store_true", help="Print install commands from manifest")
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="Exit 0 even if required deps missing (report only)",
    )
    args = parser.parse_args()
    groups = args.groups or ["minimal"]

    if args.hints:
        install_hints(load_manifest(), groups)
        return

    code = run_check(groups=groups, json_out=args.json, fail_on_required=not args.no_fail)
    if not args.json and code == 0:
        print("\nAll checked required dependencies are satisfied.")
    sys.exit(code)


if __name__ == "__main__":
    main()
