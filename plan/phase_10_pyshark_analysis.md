# Phase 10 — PyShark Analysis and MongoDB Update

## Goal

Analyze each PCAPNG capture automatically and store the traffic summary in its `iot_security.experiments` document.

## Metrics

- total and TCP packet counts;
- total captured bytes;
- minimum, maximum and average packet length;
- start/end time and duration;
- sender-to-receiver and receiver-to-sender bytes;
- retransmissions;
- key-establishment and encrypted-data totals.

## Calculations

```text
application_overhead = protocol_payload_bytes - plaintext_bytes
network_overhead = captured_bytes - plaintext_bytes
overhead_percent = network_overhead / plaintext_bytes * 100
```

Handle zero-byte plaintext separately.

## Tasks

1. Retrieve capture metadata for an experiment.
2. Open the file using `pyshark.FileCapture`.
3. Apply `tcp.port == 5000`.
4. Determine direction from the recorded sender/receiver endpoints.
5. Handle packets with missing layers safely and always close the capture.
6. Update `traffic_analysis` in the matching experiment.
7. Optionally copy profile/device aggregate network metrics into benchmark summaries.

## Example update

```python
db.experiments.update_one(
    {"_id": experiment_id},
    {"$set": {
        "traffic_analysis": summary,
        "status": "analyzed"
    }}
)
```

## Validation

Compare one result manually with Wireshark statistics and document which link/IP/TCP headers are included.

## Deliverable

`evaluation/traffic_analyzer.py`, experiment updates and comparison charts generated from MongoDB queries.

