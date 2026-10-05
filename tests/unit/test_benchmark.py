"""Unit tests for evaluation modules: memory_monitor, statistics, and benchmark (dry-run)."""

from __future__ import annotations

import time
import unittest

from evaluation.memory_monitor import (
    MemorySnapshot,
    get_current_rss_kb,
    start_memory_tracking,
    stop_memory_tracking,
)
from evaluation.statistics import Stats, compute_stats


# ------------------------------------------------------------------ #
# memory_monitor tests                                                 #
# ------------------------------------------------------------------ #

class TestMemoryMonitor(unittest.TestCase):
    def test_snapshot_type(self) -> None:
        start_memory_tracking()
        _ = bytearray(1024 * 64)  # allocate 64 KB
        snap = stop_memory_tracking()
        self.assertIsInstance(snap, MemorySnapshot)

    def test_tracemalloc_peak_nonnegative(self) -> None:
        start_memory_tracking()
        _ = bytearray(1024 * 32)
        snap = stop_memory_tracking()
        self.assertGreaterEqual(snap.tracemalloc_peak_kb, 0)

    def test_process_rss_positive(self) -> None:
        start_memory_tracking()
        snap = stop_memory_tracking()
        self.assertGreater(snap.process_rss_kb, 0)

    def test_stop_without_start_returns_zero_tracemalloc(self) -> None:
        """Calling stop without start should not raise, and peak should be 0."""
        import tracemalloc
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        snap = stop_memory_tracking()
        self.assertEqual(snap.tracemalloc_peak_kb, 0.0)

    def test_get_current_rss_kb(self) -> None:
        rss = get_current_rss_kb()
        self.assertGreater(rss, 0)

    def test_idempotent_start(self) -> None:
        """Calling start twice should not raise."""
        start_memory_tracking()
        start_memory_tracking()
        snap = stop_memory_tracking()
        self.assertIsNotNone(snap)


# ------------------------------------------------------------------ #
# statistics tests                                                     #
# ------------------------------------------------------------------ #

class TestComputeStats(unittest.TestCase):
    def test_basic_values(self) -> None:
        stats = compute_stats([1.0, 2.0, 3.0, 4.0, 5.0])
        self.assertEqual(stats.count, 5)
        self.assertAlmostEqual(stats.mean, 3.0)
        self.assertAlmostEqual(stats.median, 3.0)
        self.assertAlmostEqual(stats.minimum, 1.0)
        self.assertAlmostEqual(stats.maximum, 5.0)

    def test_single_value(self) -> None:
        stats = compute_stats([42.0])
        self.assertEqual(stats.count, 1)
        self.assertAlmostEqual(stats.mean, 42.0)
        self.assertAlmostEqual(stats.std_dev, 0.0)

    def test_even_count_median(self) -> None:
        stats = compute_stats([1.0, 3.0])
        self.assertAlmostEqual(stats.median, 2.0)

    def test_std_dev(self) -> None:
        import math
        stats = compute_stats([2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0])
        self.assertAlmostEqual(stats.std_dev, 2.138090, places=3)

    def test_p95_simple(self) -> None:
        values = list(range(1, 21))  # 1..20
        stats = compute_stats(values)
        # 95th percentile of 20 items = index ceil(0.95*20)-1 = 18 → value 19
        self.assertEqual(stats.p95, 19)

    def test_empty_raises(self) -> None:
        with self.assertRaises(ValueError):
            compute_stats([])

    def test_returns_stats_type(self) -> None:
        self.assertIsInstance(compute_stats([1.0, 2.0]), Stats)

    def test_to_dict_keys(self) -> None:
        d = compute_stats([1.0, 2.0, 3.0]).to_dict()
        for key in ("count", "mean", "median", "std_dev", "minimum", "maximum", "p95"):
            self.assertIn(key, d)


# ------------------------------------------------------------------ #
# benchmark dry-run tests                                              #
# ------------------------------------------------------------------ #

class TestBenchmarkDryRun(unittest.TestCase):
    """Smoke-tests benchmark suite logic without touching MongoDB."""

    def test_dry_run_c1(self) -> None:
        from evaluation.benchmark import run_benchmark_suite
        docs = run_benchmark_suite(
            device_id="test-device",
            repetitions=2,
            message_sizes=[64],
            profile_ids=["C1"],
            dry_run=True,
            verbose=False,
        )
        self.assertGreater(len(docs), 0)
        doc = docs[0]
        self.assertIn("run_id", doc)
        self.assertIn("timings_ms", doc)
        self.assertIn("peak_memory_kb", doc)
        self.assertIn("application_bytes", doc)
        self.assertEqual(doc["profile_id"], "C1")
        self.assertEqual(doc["message_size_bytes"], 64)

    def test_dry_run_c3(self) -> None:
        from evaluation.benchmark import run_benchmark_suite
        docs = run_benchmark_suite(
            device_id="test-device",
            repetitions=2,
            message_sizes=[64],
            profile_ids=["C3"],
            dry_run=True,
            verbose=False,
        )
        self.assertTrue(all(d["success"] for d in docs))

    def test_dry_run_all_profiles(self) -> None:
        from evaluation.benchmark import run_benchmark_suite
        docs = run_benchmark_suite(
            device_id="test-device",
            repetitions=1,
            message_sizes=[64],
            dry_run=True,
            verbose=False,
        )
        profile_ids_seen = {d["profile_id"] for d in docs}
        self.assertGreaterEqual(len(profile_ids_seen), 2)

    def test_timings_all_positive(self) -> None:
        from evaluation.benchmark import run_benchmark_suite
        docs = run_benchmark_suite(
            device_id="test-device",
            repetitions=2,
            message_sizes=[64],
            profile_ids=["C3"],
            dry_run=True,
            verbose=False,
        )
        for doc in docs:
            if doc["success"]:
                for k, v in doc["timings_ms"].items():
                    self.assertGreaterEqual(v, 0.0, msg=f"Timing '{k}' should be non-negative")

    def test_application_bytes_positive(self) -> None:
        from evaluation.benchmark import run_benchmark_suite
        docs = run_benchmark_suite(
            device_id="test-device",
            repetitions=1,
            message_sizes=[1024],
            profile_ids=["C1"],
            dry_run=True,
            verbose=False,
        )
        self.assertGreater(docs[0]["application_bytes"], 1024)

    def test_env_info_in_doc(self) -> None:
        from evaluation.benchmark import run_benchmark_suite
        docs = run_benchmark_suite(
            device_id="test-device",
            repetitions=1,
            message_sizes=[64],
            profile_ids=["C1"],
            dry_run=True,
            verbose=False,
        )
        env = docs[0]["env_info"]
        for key in ("os", "python_version", "cryptography_version"):
            self.assertIn(key, env)

    def test_run_id_unique(self) -> None:
        from evaluation.benchmark import run_benchmark_suite
        docs = run_benchmark_suite(
            device_id="test-device",
            repetitions=3,
            message_sizes=[64],
            profile_ids=["C3"],
            dry_run=True,
            verbose=False,
        )
        run_ids = [d["run_id"] for d in docs]
        self.assertEqual(len(run_ids), len(set(run_ids)))


if __name__ == "__main__":
    unittest.main()
