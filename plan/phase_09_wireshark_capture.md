# Phase 9 — Wireshark Packet Capture

## Goal

Capture each real sender-receiver exchange and correlate the PCAPNG file with its MongoDB experiment.

## Procedure

1. Create the experiment and obtain its MongoDB `_id` or public UUID.
2. Start capture on loopback, Wi-Fi or Ethernet.
3. Run exactly one controlled communication.
4. Stop after acknowledgement and TCP shutdown.
5. Save as `<experiment-id>_<profile>_<message-size>.pcapng`.
6. Store the safe local capture path/name and capture metadata in the experiment.

## Filters

```text
tcp.port == 5000
```

Use `tcp.stream eq N` to isolate one connection.

## Verification

- plaintext is absent from payload search;
- private keys and raw AES keys are absent;
- addresses, ports, sizes, directions and timing remain visible;
- key-establishment and encrypted-data stages are identifiable.

## MongoDB storage rule

Do not store large PCAPNG binary files directly in a normal experiment document. Store a file path or durable object-storage reference plus hash, size, interface, filter and capture time. GridFS is optional only if database storage of captures becomes a requirement.

## Deliverable

Correlated PCAPNG captures and updated `experiments.capture` metadata.

