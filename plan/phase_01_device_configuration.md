# Phase 1 — MongoDB Device Catalogue and Selection

## Goal

Select Device A and Device B dynamically from the `iot_security.devices` collection. Do not use `device_a.json`, `device_b.json` or hardcoded device choices.

## Device document

```json
{
  "_id": "esp32",
  "name": "ESP32",
  "manufacturer": "Espressif",
  "category": "microcontroller",
  "hardware": {
    "cpu": "Xtensa LX6",
    "cores": 2,
    "frequency_mhz": 240,
    "ram_kb": 520,
    "flash_kb": 4096
  },
  "network": {
    "interfaces": ["Wi-Fi", "Bluetooth"],
    "default_max_packet_bytes": 1024
  },
  "supported_algorithms": {
    "key_establishment": ["RSA-2048", "ECDH-P256"],
    "symmetric": ["AES-128-GCM"]
  },
  "active": true
}
```

## Runtime state

Do not permanently modify the catalogue for changing values. Collect these after device selection and store them in the experiment:

- available memory;
- current battery percentage;
- network type;
- maximum packet size;
- latency requirement; and
- sender/receiver role.

## Tasks

1. Connect through `database/connection.py`.
2. Query `{"active": true}` and sort by device name.
3. Display numbered choices and select A (sender) and B (receiver).
4. Load both complete device documents.
5. Validate their hardware and algorithm fields.
6. Collect and validate runtime state.
7. Determine the intersection of supported capabilities.
8. Save the selected device IDs and runtime snapshots in `experiments`.
9. Add CLI operations to list and add devices without changing source code.

## Suggested indexes

```python
db.devices.create_index("name", unique=True)
db.devices.create_index("active")
```

## Validation

- Device IDs must exist and be active.
- RAM and packet sizes must be positive.
- Battery must be between 0 and 100.
- Available memory cannot exceed total RAM.
- Algorithm identifiers must match profile requirements.
- The same model may be allowed for A and B if they represent separate units.

## Deliverable

`device_repository.py`, `device_selector.py`, validation tests and seeded device documents in MongoDB.

