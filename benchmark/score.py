"""Benchmark harness: score Fissure against VulnLab's known vulnerabilities.

Starts VulnLab, runs a full Fissure scan, matches the findings against
`ground_truth.json`, and reports precision / recall / F1 — overall and per
vulnerability class. This turns "I built a scanner" into "I measured it."

    python benchmark/score.py

The `headers` module (OWASP A05) is reported separately as coverage, not scored
for precision/recall, because missing-header findings are expected on nearly
every response and would skew the metrics.

A documented path for comparing against OWASP ZAP and Nikto on the same target
is in benchmark/README.md.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
import tempfile
import threading
from pathlib import Path
from wsgiref.simple_server import make_server

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmark.vulnlab import ThreadingWSGIServer, app  # noqa: E402
from fissure.engine import Engine  # noqa: E402

SCORED_CLASSES = {"sqli", "xss", "cmdi", "traversal", "ssti", "redirect", "discovery", "cors"}
PATH_KEYED = {"discovery", "cors"}  # keyed by URL path, not by a parameter
GT_PATH = Path(__file__).with_name("ground_truth.json")
_PARAM_RE = re.compile(r"\(param:\s*([^)]+)\)")


def _start_server():
    server = make_server("127.0.0.1", 0, app, server_class=ThreadingWSGIServer)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def _param_of(location: str) -> str | None:
    m = _PARAM_RE.search(location or "")
    return m.group(1).strip() if m else None


def _detected_keys(report: dict) -> set[tuple[str, str | None]]:
    """Set of (class, param) Fissure reported, for the scored classes."""
    keys: set[tuple[str, str | None]] = set()
    for module, data in report["modules"].items():
        if module not in SCORED_CLASSES:
            continue
        for f in data["findings"]:
            if module in PATH_KEYED:
                keys.add((module, _path_tail(f["location"])))
            else:
                keys.add((module, _param_of(f["location"])))
    return keys


def _path_tail(url: str) -> str:
    return "/" + url.rstrip("/").split("/")[-1]


def _gt_key(entry: dict) -> tuple[str, str | None]:
    if entry["class"] in PATH_KEYED:
        return (entry["class"], entry["path"])  # e.g. ("discovery", "/.env")
    return (entry["class"], entry["param"])


async def _run_scan(url: str) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        out = str(Path(tmp) / "report.json")
        engine = Engine(url, output=out, timeout=15, crawl_depth=1)
        return await engine.run()


def main() -> int:
    gt = json.loads(GT_PATH.read_text(encoding="utf-8"))["vulns"]
    expected = {_gt_key(e): e for e in gt}

    server, url = _start_server()
    try:
        report = asyncio.run(_run_scan(url))
    finally:
        server.shutdown()

    detected = _detected_keys(report)
    expected_keys = set(expected)

    tp = sorted(expected_keys & detected)
    fn = sorted(expected_keys - detected)
    fp = sorted(detected - expected_keys)

    precision = len(tp) / (len(tp) + len(fp)) if (tp or fp) else 1.0
    recall = len(tp) / (len(tp) + len(fn)) if (tp or fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    print("\n=== Fissure vs VulnLab ground truth ===\n")
    print(f"{'class':<12}{'param/path':<14}{'expected':<10}{'detected':<10}")
    print("-" * 46)
    for key, entry in sorted(expected.items()):
        mark = "YES" if key in detected else "MISS"
        print(f"{key[0]:<12}{str(key[1]):<14}{'yes':<10}{mark:<10}")
    for key in fp:
        print(f"{key[0]:<12}{str(key[1]):<14}{'-':<10}{'FP':<10}")

    print("\n--- Metrics (scored classes only) ---")
    print(f"True positives : {len(tp)}")
    print(f"False negatives: {len(fn)}  {fn if fn else ''}")
    print(f"False positives: {len(fp)}  {fp if fp else ''}")
    print(f"Precision      : {precision:.3f}")
    print(f"Recall         : {recall:.3f}")
    print(f"F1 score       : {f1:.3f}")

    hdr = report["modules"].get("headers", {})
    print(f"\n(headers/A05 coverage, not scored: {len(hdr.get('findings', []))} finding(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
