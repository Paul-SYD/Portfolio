# Deep Learning for Threat Detection — AI SOC Pipeline

A defensive AI Security Operations Center (SOC) pipeline built for **AICS-106: Deep Learning for Threat Detection**, part of the ICDFA AI-Driven Cybersecurity and Digital Forensics Fellowship.

This project designs, trains, evaluates, and demonstrates two complementary deep learning detectors:

- **ThreatNet** — a network-flow classifier detecting six classes of network behaviour: `benign`, `brute_force`, `reconnaissance`, `web_attack`, `botnet_c2`, `exfiltration`
- **Linux Log GRU** — a bidirectional GRU sequence model classifying Linux authentication session behaviour into four classes: `normal`, `brute_force`, `privilege_misuse`, `persistence_suspicion`

Both models are trained entirely on **synthetic, locally generated data** — no real attacks, no real victims, no third-party logs. The pipeline covers the full lifecycle: data generation, profiling, training, evaluation, explainability, and live-style incident detection with analyst-ready reporting.

> ⚠️ **This is a defensive, educational lab project.** It is not production-hardened and should not be treated as a validated real-world detector. See [Limitations](REPORT.md#risk-privacy-drift-and-limitations) in the full report.

-----

## Table of Contents

- [Project Overview](#project-overview)
- [What This Project Demonstrates](#what-this-project-demonstrates)
- [Repository Structure](#repository-structure)
- [Quick Start](#quick-start)
- [Full Documentation](#full-documentation)
- [Key Results at a Glance](#key-results-at-a-glance)
- [Tech Stack](#tech-stack)
- [Limitations](#limitations)
- [Author](#author)

-----

## Project Overview

Modern security operations centers face a flood of telemetry from network flows, authentication logs, and endpoint events — far more than human analysts can manually triage. This project explores how deep learning can support that triage process by learning to classify threat behaviour from structured network features and sequential Linux session logs, then packaging predictions into incident reports an analyst can actually act on (severity, confidence, evidence, recommended response).

The project deliberately treats **evaluation honesty** as a first-class concern: rather than reporting accuracy alone, it uses macro F1, per-class precision/recall, and confusion matrices — because in security data, benign traffic usually dominates, and accuracy alone can hide a model that misses every real attack.

## What This Project Demonstrates

- Building a reproducible Linux + Python + PyTorch environment for ML security work
- Generating and profiling synthetic security telemetry (network flow + Linux auth sequences)
- Training a residual-style deep network on structured/tabular flow data
- Training a bidirectional GRU on sequential authentication event data
- Evaluating models with security-appropriate metrics (macro F1, confusion matrix, per-class recall)
- Producing model explainability output (feature saliency) for analyst trust
- Running a live-style streaming detector that generates JSON/Markdown incident reports
- Honest documentation of risk, limitations, and what would be required before real deployment

## Repository Structure

```
.
├── README.md                          # This file — project overview
├── REPORT.md                          # Full technical write-up, step by step
├── lab_kit/
│   ├── aics106_ai_soc_pipeline.py     # Main network-flow training/detection engine
│   ├── aics106_log_sequence_model.py  # Linux log sequence model (GRU)
│   ├── requirements.txt
│   ├── datasets/                      # Generated synthetic datasets
│   ├── models/                        # Trained model checkpoints (.pt)
│   ├── reports/                       # Evaluation reports, explanations, incidents
│   └── figures/                       # Confusion matrices, plots (if generated)
└── command_transcript.txt             # Full raw command history for this run
```

## Quick Start

```bash
# 1. Set up environment
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip wheel setuptools

# 2. Install dependencies
cd lab_kit
pip install -r requirements.txt

# 3. Verify environment
python - <<'PY'
import sys, torch, sklearn, pandas as pd
print('Python:', sys.version)
print('PyTorch:', torch.__version__)
print('CUDA available:', torch.cuda.is_available())
print('Pandas:', pd.__version__)
print('Scikit-learn:', sklearn.__version__)
PY

# 4. Self-test
python aics106_ai_soc_pipeline.py self-test
```

See <REPORT.md> for the complete step-by-step procedure, every command used, full output/results, and analysis.

## Full Documentation

📄 **<REPORT.md>** contains the complete technical write-up:

- Full methodology with every command run, in order
- Dataset schema and class distributions
- Model architectures and training configuration
- Evaluation results and confusion matrix analysis
- Explainability output and analyst triage examples
- Live SOC demo output and sample incidents
- Risk, privacy, drift, and limitations
- Deployment recommendations

## Key Results at a Glance

|Model        |Task                                |Macro F1|Notes                   |
|-------------|------------------------------------|--------|------------------------|
|ThreatNet    |6-class network flow classification |0.9998  |30,000 synthetic records|
|Linux Log GRU|4-class auth sequence classification|1.00    |8,000 synthetic sessions|

**Note:** These near-perfect scores reflect the separability of synthetic training data, not validated real-world performance. See [Limitations](REPORT.md#risk-privacy-drift-and-limitations).

## Tech Stack

- **Language:** Python 3
- **ML Framework:** PyTorch
- **Data:** pandas, numpy
- **Evaluation:** scikit-learn
- **Environment:** Ubuntu 24.04 LTS, CPU-only training

## Limitations

This project uses **synthetic data only** and has not been validated against real-world or public benchmark traffic (e.g. UNSW-NB15, CIC-IDS2017). Results should be read as a proof-of-concept demonstration of the full pipeline, not a production-ready detector. Full discussion in [REPORT.md](REPORT.md#risk-privacy-drift-and-limitations).

## Author

**Yohanna Paul Sheawaza**
AI-Driven Cybersecurity and Digital Forensics Fellowship — ICDFA
Course: AICS-106, Deep Learning for Threat Detection