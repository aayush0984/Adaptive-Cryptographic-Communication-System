# Phase 6 — MongoDB-Backed Performance Benchmarking

## Goal

Measure every profile fairly and store reproducible observations in `iot_security.benchmarks`.

## Measurements

- key-pair generation;
- RSA wrap/unwrap or ECDH/HKDF;
- AES encryption/decryption;
- total time;
- peak memory;
- application bytes;
- success status.

Network capture metrics are added after Phase 10.

## Benchmark document

```json
{
  "run_id": "uuid",
  "device_id": "esp32",
  "profile_id": "C3",
  "message_size_bytes": 1024,
  "repetition": 1,
  "timings_ms": {
    "key_generation": 17.4,
    "key_establishment": 8.6,
    "encryption": 0.72,
    "decryption": 0.68,
    "total": 27.4
  },
  "peak_memory_kb": 42.5,
  "application_bytes": 1178,
  "measurement_source": "simulated",
  "measured_at": "ISODate"
}
```

## Procedure

Use 64 B, 1 KB, 10 KB and 100 KB messages; perform a warm-up and at least 30 recorded repetitions. Use `perf_counter_ns()`, `tracemalloc` and `psutil`. Store raw runs, then compute summaries without destroying raw data.

## Data integrity

Record OS, CPU, RAM, Python/library versions and one of: `physical-device`, `local-computer`, `published`, or `simulated`. Never label laptop results as physical-device results for another IoT board.

## Indexes

```python
db.benchmarks.create_index([
    ("device_id", 1),
    ("profile_id", 1),
    ("message_size_bytes", 1),
    ("measurement_source", 1)
])
db.benchmarks.create_index("run_id", unique=True)
```

## Deliverable

`evaluation/benchmark.py`, MongoDB raw runs, aggregation queries and summary reports.

