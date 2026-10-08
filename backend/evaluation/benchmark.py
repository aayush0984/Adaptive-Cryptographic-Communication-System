"""Phase 6 — MongoDB-backed performance benchmarking engine.

Measures every crypto profile fairly across configurable message sizes,
stores reproducible raw observations in ``iot_security.benchmarks``, and
provides summary/aggregation helpers.

Usage (CLI):
    python -m evaluation.benchmark --all
    python -m evaluation.benchmark --device esp32 --repetitions 30
    python -m evaluation.benchmark --all --profiles C5
    python -m evaluation.benchmark --all --profiles C1 C2 C3

Usage (programmatic):
    from evaluation.benchmark import run_benchmark_suite
    run_benchmark_suite(device_id="esp32", repetitions=5, dry_run=True)
"""

from __future__ import annotations

import os
import platform
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from database.connection import get_database
from evaluation.memory_monitor import start_memory_tracking, stop_memory_tracking
from evaluation.statistics import compute_stats
from repositories.profile_repository import ProfileRepository

# --------------------------------------------------------------------------- #
# Default benchmark parameters                                                  #
# --------------------------------------------------------------------------- #

#: Message sizes to benchmark (bytes)
MESSAGE_SIZES: list[int] = [64, 1024, 10_240, 102_400, 1024_000]  # 64B, 1KB, 10KB, 100KB, 1MB

#: Number of warm-up iterations (discarded)
WARMUP_REPS: int = 3

#: Default number of recorded repetitions
DEFAULT_REPS: int = 30

MEASUREMENT_SOURCE = "local-computer"


# --------------------------------------------------------------------------- #
# Internal helpers                                                              #
# --------------------------------------------------------------------------- #

def _ns_to_ms(ns: int) -> float:
    return round(ns / 1_000_000, 6)


def _build_env_info() -> dict[str, str]:
    """Capture OS/runtime metadata for data-integrity compliance."""
    from cryptography import __version__ as crypto_ver  # local import to avoid circular deps
    import pymongo

    return {
        "os": platform.system(),
        "os_version": platform.version(),
        "cpu_arch": platform.machine(),
        "python_version": sys.version.split()[0],
        "cryptography_version": crypto_ver,
        "pymongo_version": pymongo.__version__,
        "cpu_count": str(os.cpu_count() or "unknown"),
    }


# --------------------------------------------------------------------------- #
# Per-profile benchmark functions                                               #
# --------------------------------------------------------------------------- #

def _benchmark_rsa_profile(
    profile: Any,
    message: bytes,
) -> dict[str, float]:
    """Time RSA key generation, wrap, encrypt, decrypt, unwrap."""
    from crypto import rsa_engine, aes_engine

    key_size = int(profile.key_establishment["parameter"])
    aes_key_size = profile.symmetric_encryption["key_size_bits"]

    # ---- key generation ----
    t0 = time.perf_counter_ns()
    priv_key = rsa_engine.generate_key_pair(key_size)
    pub_key = priv_key.public_key()
    key_gen_ms = _ns_to_ms(time.perf_counter_ns() - t0)

    # ---- key establishment (wrap AES key with RSA-OAEP) ----
    aes_key = aes_engine.generate_key(aes_key_size)
    t0 = time.perf_counter_ns()
    wrapped = rsa_engine.wrap_aes_key(aes_key, pub_key)
    unwrapped = rsa_engine.unwrap_aes_key(wrapped, priv_key)
    key_est_ms = _ns_to_ms(time.perf_counter_ns() - t0)

    assert unwrapped == aes_key

    # ---- AES encryption ----
    plaintext = message.decode("latin-1")  # bytes → str for encrypt_message
    t0 = time.perf_counter_ns()
    ciphertext, nonce = aes_engine.encrypt_message(plaintext, aes_key)
    enc_ms = _ns_to_ms(time.perf_counter_ns() - t0)

    # ---- AES decryption ----
    t0 = time.perf_counter_ns()
    _ = aes_engine.decrypt_message(ciphertext, nonce, aes_key)
    dec_ms = _ns_to_ms(time.perf_counter_ns() - t0)

    total_ms = round(key_gen_ms + key_est_ms + enc_ms + dec_ms, 6)

    # application bytes = wrapped key + nonce + ciphertext
    app_bytes = len(wrapped) + len(nonce) + len(ciphertext)

    return {
        "timings_ms": {
            "key_generation": key_gen_ms,
            "key_establishment": key_est_ms,
            "encryption": enc_ms,
            "decryption": dec_ms,
            "total": total_ms,
        },
        "application_bytes": app_bytes,
    }


def _benchmark_ecc_profile(
    profile: Any,
    message: bytes,
) -> dict[str, float]:
    """Time ECDH key generation, HKDF derivation, AES encrypt/decrypt."""
    from crypto import ecc_engine, aes_engine

    curve_name = profile.key_establishment["parameter"]  # "P-256" or "P-384"
    aes_key_size = profile.symmetric_encryption["key_size_bits"]

    # ---- key generation (sender & receiver ephemeral keys) ----
    t0 = time.perf_counter_ns()
    sender_priv = ecc_engine.generate_key_pair(curve_name)
    sender_pub = sender_priv.public_key()
    receiver_priv = ecc_engine.generate_key_pair(curve_name)
    receiver_pub = receiver_priv.public_key()
    key_gen_ms = _ns_to_ms(time.perf_counter_ns() - t0)

    # ---- key establishment: ECDH + HKDF ----
    salt = ecc_engine.generate_salt(16)
    t0 = time.perf_counter_ns()
    shared_sender = ecc_engine.perform_ecdh(sender_priv, receiver_pub)
    aes_key = ecc_engine.derive_aes_key(shared_sender, salt, aes_key_size)
    # receiver side (verification)
    shared_receiver = ecc_engine.perform_ecdh(receiver_priv, sender_pub)
    aes_key_recv = ecc_engine.derive_aes_key(shared_receiver, salt, aes_key_size)
    key_est_ms = _ns_to_ms(time.perf_counter_ns() - t0)

    assert aes_key == aes_key_recv

    # ---- AES encryption ----
    plaintext = message.decode("latin-1")
    t0 = time.perf_counter_ns()
    ciphertext, nonce = aes_engine.encrypt_message(plaintext, aes_key)
    enc_ms = _ns_to_ms(time.perf_counter_ns() - t0)

    # ---- AES decryption ----
    t0 = time.perf_counter_ns()
    _ = aes_engine.decrypt_message(ciphertext, nonce, aes_key_recv)
    dec_ms = _ns_to_ms(time.perf_counter_ns() - t0)

    total_ms = round(key_gen_ms + key_est_ms + enc_ms + dec_ms, 6)

    # application bytes = sender public key pem + salt + nonce + ciphertext
    sender_pub_pem = ecc_engine.serialize_public_key(sender_pub)
    app_bytes = len(sender_pub_pem) + len(salt) + len(nonce) + len(ciphertext)

    return {
        "timings_ms": {
            "key_generation": key_gen_ms,
            "key_establishment": key_est_ms,
            "encryption": enc_ms,
            "decryption": dec_ms,
            "total": total_ms,
        },
        "application_bytes": app_bytes,
    }


def _benchmark_psk_profile(
    profile: Any,
    message: bytes,
) -> dict[str, float]:
    """Time PSK encryption and decryption (AES-128-GCM)."""
    from crypto import psk_engine

    psk_key = psk_engine.get_psk_key()

    # Pre-shared key: key generation and key establishment over wire are 0.0 ms
    key_gen_ms = 0.0
    key_est_ms = 0.0

    # ---- AES encryption ----
    plaintext = message.decode("latin-1")
    t0 = time.perf_counter_ns()
    ciphertext, nonce = psk_engine.encrypt_with_psk(plaintext, psk_key)
    enc_ms = _ns_to_ms(time.perf_counter_ns() - t0)

    # ---- AES decryption ----
    t0 = time.perf_counter_ns()
    _ = psk_engine.decrypt_with_psk(ciphertext, nonce, psk_key)
    dec_ms = _ns_to_ms(time.perf_counter_ns() - t0)

    total_ms = round(key_gen_ms + key_est_ms + enc_ms + dec_ms, 6)

    # application bytes = nonce (12) + ciphertext (includes 16-byte auth tag)
    app_bytes = len(nonce) + len(ciphertext)

    return {
        "timings_ms": {
            "key_generation": key_gen_ms,
            "key_establishment": key_est_ms,
            "encryption": enc_ms,
            "decryption": dec_ms,
            "total": total_ms,
        },
        "application_bytes": app_bytes,
    }


# --------------------------------------------------------------------------- #
# Single-run record                                                             #
# --------------------------------------------------------------------------- #

def _run_single(
    profile: Any,
    message: bytes,
    device_id: str,
    repetition: int,
    env_info: dict[str, str],
) -> dict[str, Any]:
    """Execute one timed + memory-profiled benchmark repetition."""
    family = profile.key_establishment["family"]

    start_memory_tracking()
    try:
        if family == "RSA":
            result = _benchmark_rsa_profile(profile, message)
        elif family == "ECC":
            result = _benchmark_ecc_profile(profile, message)
        elif family == "PSK":
            result = _benchmark_psk_profile(profile, message)
        else:
            raise ValueError(f"Unsupported key establishment family: {family}")
        success = True
        error_message = None
    except Exception as exc:
        result = {
            "timings_ms": {
                "key_generation": 0.0,
                "key_establishment": 0.0,
                "encryption": 0.0,
                "decryption": 0.0,
                "total": 0.0,
            },
            "application_bytes": 0,
        }
        success = False
        error_message = str(exc)
    finally:
        mem = stop_memory_tracking()

    benchmark_mode = "simulated" if MEASUREMENT_SOURCE in ("local-computer", "estimated-scaled") else "measured"

    return {
        "run_id": str(uuid.uuid4()),
        "device_id": device_id,
        "profile_id": profile.profile_id,
        "message_size_bytes": len(message),
        "repetition": repetition,
        "timings_ms": result["timings_ms"],
        "peak_memory_kb": mem.tracemalloc_peak_kb,
        "process_rss_kb": mem.process_rss_kb,
        "application_bytes": result["application_bytes"],
        "measurement_source": MEASUREMENT_SOURCE,
        "benchmark_mode": benchmark_mode,
        "success": success,
        "error_message": error_message,
        "env_info": env_info,
        "measured_at": datetime.now(tz=timezone.utc),
    }


# --------------------------------------------------------------------------- #
# Public API                                                                    #
# --------------------------------------------------------------------------- #

def run_benchmark_suite(
    device_id: str,
    repetitions: int = DEFAULT_REPS,
    message_sizes: list[int] | None = None,
    profile_ids: list[str] | None = None,
    dry_run: bool = False,
    verbose: bool = True,
) -> list[dict[str, Any]]:
    """Run the full benchmarking suite for every (profile × message_size) pair.

    Args:
        device_id: Identifier used in every benchmark document (e.g., ``"esp32"``).
        repetitions: Number of recorded repetitions (warm-up is additional).
        message_sizes: Override default ``[64, 1024, 10240, 102400]`` bytes.
        profile_ids: Restrict to specific profile IDs; ``None`` → all active profiles.
        dry_run: If ``True``, run benchmarks but skip writing to MongoDB.
        verbose: Print progress to stdout.

    Returns:
        List of all raw benchmark documents produced (regardless of ``dry_run``).
    """
    sizes = message_sizes or MESSAGE_SIZES
    env_info = _build_env_info()
    repo = ProfileRepository()
    profiles = repo.list_enabled()

    if profile_ids:
        profiles = [p for p in profiles if p.profile_id in profile_ids]

    if not profiles:
        raise ValueError("No enabled crypto profiles found. Seed the database first.")

    db = get_database() if not dry_run else None
    col = db["benchmarks"] if db is not None else None

    all_docs: list[dict[str, Any]] = []

    for profile in profiles:
        for size in sizes:
            message = os.urandom(size)

            if verbose:
                print(f"  Benchmarking {profile.profile_id} | {size:>7} B  ", end="", flush=True)

            # Warm-up (not recorded)
            for _ in range(WARMUP_REPS):
                try:
                    _run_single(profile, message, device_id, 0, env_info)
                except Exception:
                    pass

            # Recorded repetitions
            reps_docs: list[dict[str, Any]] = []
            for rep in range(1, repetitions + 1):
                doc = _run_single(profile, message, device_id, rep, env_info)
                reps_docs.append(doc)

            if col is not None:
                for doc in reps_docs:
                    try:
                        col.update_one(
                            {
                                "device_id": doc["device_id"],
                                "profile_id": doc["profile_id"],
                                "message_size_bytes": doc["message_size_bytes"],
                                "repetition": doc["repetition"],
                            },
                            {"$set": doc},
                            upsert=True,
                        )
                    except Exception as exc:
                        print(f"\n    [ERROR] DB upsert failed for device '{doc['device_id']}', profile '{doc['profile_id']}': {exc}", flush=True)
                        raise

            all_docs.extend(reps_docs)

            if verbose:
                success_docs = [d for d in reps_docs if d["success"]]
                if success_docs:
                    totals = [d["timings_ms"]["total"] for d in success_docs]
                    avg = sum(totals) / len(totals)
                    print(f"avg {avg:.2f} ms  ({len(success_docs)}/{repetitions} ok)")
                else:
                    print("ALL FAILED")

    return all_docs


def aggregate_summary(
    device_id: str | None = None,
    profile_id: str | None = None,
    message_size_bytes: int | None = None,
    measurement_source: str | None = None,
) -> list[dict[str, Any]]:
    """Retrieve raw runs from MongoDB and compute descriptive statistics.

    All args are optional filters. Returns one summary dict per unique
    (profile_id, message_size_bytes) combination found.
    """
    query: dict[str, Any] = {"success": True}
    if device_id:
        query["device_id"] = device_id
    if profile_id:
        query["profile_id"] = profile_id
    if message_size_bytes is not None:
        query["message_size_bytes"] = message_size_bytes
    if measurement_source:
        query["measurement_source"] = measurement_source

    db = get_database()
    col = db["benchmarks"]
    docs = list(col.find(query))

    if not docs:
        return []

    # Group by (profile_id, message_size_bytes)
    groups: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for doc in docs:
        key = (doc["profile_id"], doc["message_size_bytes"])
        groups.setdefault(key, []).append(doc)

    summaries: list[dict[str, Any]] = []
    for (pid, msize), group_docs in sorted(groups.items()):
        timing_keys = ["key_generation", "key_establishment", "encryption", "decryption", "total"]
        timing_stats = {}
        for tk in timing_keys:
            vals = [d["timings_ms"][tk] for d in group_docs if tk in d.get("timings_ms", {})]
            if vals:
                timing_stats[tk] = compute_stats(vals).to_dict()

        mem_vals = [d["peak_memory_kb"] for d in group_docs if "peak_memory_kb" in d]
        app_byte_vals = [d["application_bytes"] for d in group_docs if "application_bytes" in d]

        summaries.append({
            "profile_id": pid,
            "message_size_bytes": msize,
            "sample_count": len(group_docs),
            "timings_ms_stats": timing_stats,
            "peak_memory_kb_stats": compute_stats(mem_vals).to_dict() if mem_vals else {},
            "application_bytes_stats": compute_stats(app_byte_vals).to_dict() if app_byte_vals else {},
            "device_ids": list({d["device_id"] for d in group_docs}),
            "measurement_sources": list({d["measurement_source"] for d in group_docs}),
        })

    return summaries


# --------------------------------------------------------------------------- #
# CLI entry point                                                               #
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import argparse
    from repositories.device_repository import DeviceRepository

    parser = argparse.ArgumentParser(description="Phase 6 — IoT Crypto Benchmarking")
    parser.add_argument("--device", help="Device ID (e.g. esp32, raspberry_pi_4)")
    parser.add_argument("--all", action="store_true", help="Benchmark all active devices in MongoDB catalog")
    parser.add_argument("--repetitions", type=int, default=DEFAULT_REPS)
    parser.add_argument("--message-sizes", nargs="+", type=int, default=None)
    parser.add_argument("--profiles", nargs="+", default=None, help="Profile IDs to benchmark (e.g. C1 C3)")
    parser.add_argument("--dry-run", action="store_true", help="Do not write results to MongoDB")
    args = parser.parse_args()

    if not args.device and not args.all:
        parser.error("Either --device or --all must be specified.")

    dev_repo = DeviceRepository()
    devices_to_run = []
    if args.all:
        devices_to_run = [d.device_id for d in dev_repo.list_active()]
    else:
        # Validate that the requested device actually exists
        dev = dev_repo.get_by_id(args.device)
        if dev is None:
            available = [d.device_id for d in dev_repo.list_active()]
            parser.error(
                f"Device '{args.device}' does not exist in the active device catalog. "
                f"Available devices: {available}"
            )
        devices_to_run = [dev.device_id]

    print(f"\nTarget device(s) for benchmarking ({len(devices_to_run)}): {devices_to_run}")

    for dev_id in devices_to_run:
        print(f"\nStarting benchmark suite for device '{dev_id}'")
        print(f"  Repetitions : {args.repetitions}")
        print(f"  Message sizes: {args.message_sizes or MESSAGE_SIZES}")
        print(f"  Dry run     : {args.dry_run}\n")

        run_benchmark_suite(
            device_id=dev_id,
            repetitions=args.repetitions,
            message_sizes=args.message_sizes,
            profile_ids=args.profiles,
            dry_run=args.dry_run,
            verbose=True,
        )

    print("\nDone.")
