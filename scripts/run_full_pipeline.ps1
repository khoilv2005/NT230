# End-to-end LAMPS reproduction on D1.
# Run from the repository root in PowerShell.

$ErrorActionPreference = "Stop"

Write-Host "[1/3] Preparing D1 splits..." -ForegroundColor Cyan
python -m lamps.data.prepare_d1

Write-Host "[2/3] Fine-tuning CodeBERT on D1..." -ForegroundColor Cyan
python -m experiments.train_codebert

Write-Host "[3/3] Evaluating LAMPS on D1..." -ForegroundColor Cyan
python -m experiments.evaluate_d1

Write-Host "Done. Results saved under results/d1/." -ForegroundColor Green
