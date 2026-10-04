# Adaptive IoT Cryptographic Selection

This repository implements secure sender–receiver communication between two
IoT devices, adaptive selection of a mutually supported cryptographic profile,
and Wireshark/PyShark traffic analysis.

Device records, cryptographic profiles, benchmark observations and experiment
results are stored in the MongoDB database `iot_security`, using the
`devices`, `crypto_profiles`, `benchmarks` and `experiments` collections.
Device A and Device B are runtime roles assigned to two records selected from
the `devices` collection; they are not separate JSON configuration files.

## Phase 2: AES-GCM engine

Install and run the tests:

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Basic usage:

```python
from crypto.aes_engine import decrypt_message, encrypt_message, generate_key

key = generate_key(128)
ciphertext, nonce = encrypt_message("Temperature = 31.4 C", key)
message = decrypt_message(ciphertext, nonce, key)
```

The ciphertext and nonce stay as bytes inside the cryptographic layer. A later
protocol phase will Base64-encode them only when constructing JSON messages.
