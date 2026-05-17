#!/usr/bin/env bash
# End-to-end LAMPS reproduction on D1.
# Run from the repository root.

set -euo pipefail

echo "[1/3] Preparing D1 splits..."
python -m lamps.data.prepare_d1

echo "[2/3] Fine-tuning CodeBERT on D1..."
python -m experiments.train_codebert

echo "[3/3] Evaluating LAMPS on D1..."
python -m experiments.evaluate_d1

echo "Done. Results saved under results/d1/."
