"""Phase 10 — PyShark Traffic Analysis CLI.

Analyzes Phase 9 .pcapng network captures and records the analysis in MongoDB.

Usage:
    python analyze_traffic.py --experiment exp-a207ff8e
    python analyze_traffic.py --pending
    python analyze_traffic.py --all
    python analyze_traffic.py --list
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from analysis.traffic_analyzer import TrafficAnalyzer


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Phase 10 — Network Traffic Analysis with PyShark",
    )
    parser.add_argument(
        "--experiment",
        "-e",
        help="Analyze a specific experiment capture (e.g. exp-a207ff8e)",
    )
    parser.add_argument(
        "--all",
        "-a",
        action="store_true",
        help="Analyze all captures in the traffic collection",
    )
    parser.add_argument(
        "--pending",
        "-p",
        action="store_true",
        help="Analyze all pending / unanalyzed captures",
    )
    parser.add_argument(
        "--list",
        "-l",
        action="store_true",
        help="List available captures in MongoDB and their analysis status",
    )
    parser.add_argument(
        "--no-persist",
        action="store_true",
        help="Run analysis without saving results to MongoDB",
    )
    return parser.parse_args()


def list_captures(analyzer: TrafficAnalyzer) -> None:
    """Print a summary table of all recorded captures."""
    docs = list(analyzer.db["traffic"].find({}))
    if not docs:
        print("[ANALYSIS] No traffic captures found in MongoDB.", flush=True)
        return

    print("============================== TRAFFIC CAPTURES ==============================", flush=True)
    print(f"{'Experiment ID':<16} {'Profile':<8} {'Msg Size':<10} {'File':<38} {'Status':<12}", flush=True)
    print("-" * 88, flush=True)
    for doc in docs:
        exp_id = doc.get("experiment_id", "unknown")
        prof = doc.get("profile_id", "unknown")
        msg_size = doc.get("message_size_bytes")
        if msg_size is None:
            msg_size = analyzer._resolve_message_size(exp_id, doc, None)
        msg_size_str = f"{msg_size} B" if msg_size is not None else "-"
        capture_file = doc.get("capture_file", "")
        # Shorten filename if too long
        display_file = capture_file.split("/")[-1] if "/" in capture_file else capture_file
        analysis = doc.get("traffic_analysis", {})
        analysis_status = analysis.get("analysis_status", "pending") if analysis else "pending"
        print(f"{exp_id:<16} {prof:<8} {msg_size_str:<10} {display_file:<38} {analysis_status:<12}", flush=True)
    print("==============================================================================", flush=True)


def main() -> int:
    args = parse_args()
    analyzer = TrafficAnalyzer()

    if args.list:
        list_captures(analyzer)
        return 0

    persist = not args.no_persist

    if args.experiment:
        analysis = analyzer.analyze_experiment(args.experiment, persist=persist)
        print(analyzer.format_summary(args.experiment, analysis), flush=True)
        return 0 if analysis.get("analysis_status") == "completed" else 1

    if args.all:
        results = analyzer.analyze_all(persist=persist)
        if not results:
            print("[ANALYSIS] No captures found in traffic collection.", flush=True)
            return 0
        overall_ok = True
        for item in results:
            exp_id = item["experiment_id"]
            analysis = item["analysis"]
            print(analyzer.format_summary(exp_id, analysis), flush=True)
            print()
            if analysis.get("analysis_status") != "completed":
                overall_ok = False
        return 0 if overall_ok else 1

    # Default or --pending: Analyze pending captures
    results = analyzer.analyze_pending(persist=persist)
    if not results:
        print("[ANALYSIS] No pending captures to analyze. Use --all to re-analyze all or --list to inspect.", flush=True)
        return 0

    overall_ok = True
    for item in results:
        exp_id = item["experiment_id"]
        analysis = item["analysis"]
        print(analyzer.format_summary(exp_id, analysis), flush=True)
        print()
        if analysis.get("analysis_status") != "completed":
            overall_ok = False

    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())

