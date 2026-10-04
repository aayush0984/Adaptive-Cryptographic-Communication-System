# Phase 7 — Adaptive Configuration Selection

## Goal

Use documents from `devices`, `crypto_profiles` and `benchmarks` to select the lowest-cost valid profile for the chosen sender and receiver.

## Data loading

1. Load both selected device documents.
2. Load their experiment-specific runtime states.
3. Query enabled profiles.
4. Query the best applicable benchmark set for each device/profile/message-size combination.
5. Prefer physical-device measurements, then clearly identified alternatives.

## Mandatory filtering

Reject a profile when either device lacks a required capability, security is insufficient, sender or receiver memory is exceeded, predicted latency is too high, or communication limits are violated.

Check endpoint resources separately; do not add A and B's RAM together.

## Scoring

Normalize cost metrics and minimize:

```text
score = wt*time + wm*memory + wc*communication + we*energy_proxy
```

Weights sum to 1 and may change for low-battery, low-memory, slow-network or real-time scenarios. Handle equal values without division by zero and use deterministic tie-breaking.

## Experiment record

Create or update an `experiments` document containing:

- device IDs and runtime snapshots;
- requested security and message size;
- candidate and rejected profile IDs;
- rejection reasons;
- normalized metrics and weights;
- winning profile ID, score and explanation;
- benchmark IDs used in the decision;
- status and timestamps.

## Failure behavior

If no profile qualifies, stop before encryption and store status `selection_failed` with complete reasons.

## Deliverable

`selection/compatibility.py`, `scoring.py`, `selector.py`, repository queries and scenario tests.

