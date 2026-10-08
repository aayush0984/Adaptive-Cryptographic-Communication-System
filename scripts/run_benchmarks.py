"""Script entrypoint: run the benchmark suite from the command line.

Usage:
    python -m scripts.run_benchmarks --device esp32 --repetitions 30
    python -m scripts.run_benchmarks --device raspberry_pi_4 --dry-run
"""

from evaluation.benchmark import run_benchmark_suite, aggregate_summary, MESSAGE_SIZES, DEFAULT_REPS

import argparse
import json


def main() -> None:
    parser = argparse.ArgumentParser(description="Run IoT crypto benchmark suite")
    parser.add_argument("--device", help="Device ID from MongoDB (e.g. esp32)")
    parser.add_argument("--all", action="store_true", help="Benchmark all active devices in MongoDB catalog")
    parser.add_argument("--repetitions", type=int, default=DEFAULT_REPS)
    parser.add_argument("--message-sizes", nargs="+", type=int, default=None)
    parser.add_argument("--profiles", nargs="+", default=None, help="Profile IDs (e.g. C1 C3)")
    parser.add_argument("--dry-run", action="store_true", help="Skip writing to MongoDB")
    parser.add_argument("--summary", action="store_true", help="Print aggregated summary after benchmarks")
    args = parser.parse_args()

    if not args.device and not args.all:
        parser.error("Either --device or --all must be specified.")

    from repositories.device_repository import DeviceRepository
    dev_repo = DeviceRepository()
    devices_to_run = [d.device_id for d in dev_repo.list_active()] if args.all else [args.device]

    for dev_id in devices_to_run:
        print(f"\nStarting benchmark suite for device '{dev_id}'")
        print(f"  Repetitions  : {args.repetitions}")
        print(f"  Message sizes: {args.message_sizes or MESSAGE_SIZES}")
        print(f"  Profiles     : {args.profiles or 'all active'}")
        print(f"  Dry run      : {args.dry_run}\n")

        run_benchmark_suite(
            device_id=dev_id,
            repetitions=args.repetitions,
            message_sizes=args.message_sizes,
            profile_ids=args.profiles,
            dry_run=args.dry_run,
            verbose=True,
        )

        if args.summary and not args.dry_run:
            print(f"\n--- Aggregated Summary for {dev_id} ---")
            summaries = aggregate_summary(device_id=dev_id)
            for s in summaries:
                pid = s["profile_id"]
                msize = s["message_size_bytes"]
                n = s["sample_count"]
                total = s.get("timings_ms_stats", {}).get("total", {})
                avg_ms = total.get("mean", "N/A")
                mem = s.get("peak_memory_kb_stats", {}).get("mean", "N/A")
                print(f"  {pid:4s} | {msize:>7} B | n={n:>3} | avg_total={avg_ms:.3f} ms | avg_mem={mem:.1f} KB")

    print("\nDone.")
    return


if __name__ == "__main__":
    main()
