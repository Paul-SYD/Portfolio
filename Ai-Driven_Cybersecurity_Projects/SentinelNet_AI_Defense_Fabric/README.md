# SentinelNet AI Defense Fabric

**Capstone Project — AICS-109: AI for Advanced Network Defense**
**AI-Driven Cybersecurity and Digital Forensics Fellowship (ICDFA)**

## Executive Summary

SentinelNet AI Defense Fabric is an AI-driven network defense pipeline combining supervised classification, unsupervised anomaly detection, sequence modeling, and telemetry fusion to detect and prioritize network threats. Built entirely on a 50,000-row synthetic flow dataset, it trains three model families (a residual MLP classifier, IsolationForest + autoencoder anomaly detectors, and a sequence model), fuses their output with simulated Zeek/Suricata telemetry, maps findings to MITRE ATT&CK, and produces a safe, dry-run-only containment plan requiring human approval on every recommendation. A core theme throughout is honest evaluation: several results (a suspiciously perfect classifier, a sequence model that failed to learn) are reported transparently rather than presented as unqualified successes — see [Known Limitations](#known-limitations) below and the full analysis in [`REPORT.md`](./REPORT.md).

## Scenario

We are the AI security engineering team for a government/enterprise SOC (Security Operations Center). We have been tasked with building a defensive AI system that can detect abnormal and malicious network behaviour, correlate alerts across multiple telemetry sources, generate incident reports, and recommend safe containment actions. The project is strictly defensive: it does not involve exploitation of public systems, credential theft, malware deployment, or unauthorized scanning. All data used is synthetic and locally generated, and all response/containment actions remain simulated (dry-run only), requiring explicit human approval before any real action would ever be taken.

## Overview

SentinelNet AI Defense Fabric is a defensive AI network monitoring pipeline built entirely on synthetic, lab-generated network telemetry. It ingests flow-level data, applies three distinct model families (supervised classification, unsupervised anomaly detection, and sequence modelling), fuses the results with simulated Zeek/Suricata-style telemetry, maps findings to MITRE ATT&CK, and produces a safe, dry-run-only containment recommendation for analyst review.

The pipeline covers 10 labs end to end:

1. Generate synthetic network flow telemetry (50,000 records, 6 classes)
1. Profile and analyze the dataset for quality and class balance
1. Engineer and evaluate features relevant to network defense
1. Train a residual MLP classifier for supervised multiclass intrusion detection
1. Train an IsolationForest and a deep autoencoder for unsupervised anomaly detection
1. Train a sequence model to look for temporal/behavioural attack patterns
1. Fuse model outputs with simulated Zeek/Suricata telemetry and map findings to MITRE ATT&CK
1. Run a streaming detection engine and measure latency/threshold trade-offs
1. Generate a dry-run-only, human-approval-required containment plan
1. Produce an auto-generated incident report and support full analyst reporting

Full step-by-step commands, raw output, and analysis for every lab are documented in [`REPORT.md`](./REPORT.md).

## Project Structure

```
SentinelNetAI_Project/
├── config.json
├── data/
│   └── synthetic_flows.csv
├── docs/
├── models/
│   ├── supervised_ids.pt
│   ├── autoencoder.pt
│   ├── isolation_forest.joblib
│   └── sequence_gru.pt
├── notebooks/
├── outputs/
│   ├── data_profile.json
│   ├── supervised_metrics.json
│   ├── anomaly_metrics.json
│   ├── sequence_metrics.json
│   ├── stream_alerts.jsonl
│   ├── fusion_summary.json
│   ├── incident_report.md
│   └── response_plan_lab_only.json
├── sample_logs/
│   ├── suricata_eve_sample.jsonl
│   └── zeek_conn_sample.jsonl
├── scripts/
│   ├── 00_generate_synthetic_network_data.py
│   ├── 01_profile_dataset.py
│   ├── 02_train_supervised_ids.py
│   ├── 03_train_autoencoder_anomaly.py
│   ├── 04_train_sequence_gru.py
│   ├── 05_run_streaming_detector.py
│   ├── 06_generate_incident_report.py
│   └── 07_response_simulator.py
├── README.md
├── REPORT.md
└── requirements.txt
```

## Environment

- **OS:** Ubuntu 24.04 LTS (VM, VMware Workstation, CPU-only)
- **Python:** 3.12.3
- **Key libraries:** PyTorch, pandas, scikit-learn, numpy

## Setup

```bash
cd SentinelNetAI_Project
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Key Results Summary

|Model                              |Metric  |Result                                                       |
|-----------------------------------|--------|-------------------------------------------------------------|
|Residual MLP (supervised)          |Macro F1|1.00 (see REPORT.md — synthetic data too separable)          |
|Autoencoder (anomaly)              |Accuracy|0.766 (high precision, low recall)                           |
|IsolationForest (anomaly)          |Accuracy|0.839 (balanced precision/recall)                            |
|Sequence model (rolling-window MLP)|Macro F1|0.127 (collapsed to majority class — documented failure)     |
|Streaming detector                 |Latency |~33ms/record average                                         |
|Response simulator                 |Actions |100% dry-run, human approval required on every recommendation|

## Table of Contents — REPORT.md

`REPORT.md` contains the full technical record of this project, in the order it was carried out:

1. Scenario
1. Environment Setup
1. Lab 1 — Environment Readiness and Project Bootstrap
1. Lab 2 — Dataset Generation, Schema Design and Data Profiling
1. Lab 3 — Feature Engineering for Network Defense
1. Lab 4 — Supervised Deep IDS Classifier
1. Lab 5 — Unsupervised Anomaly Detection
1. Lab 6 — Sequence Modelling for Behavioural Detection
1. Lab 7 — Zeek and Suricata Style Telemetry Fusion
1. Lab 8 — Streaming AI Detection Engine
1. Lab 9 — AI Response Simulator
1. Lab 10 — Capstone Defense and Analyst Reporting
1. Full Evidence Checklist
1. Overall Project Limitations

## Known Limitations

- The supervised classifier’s perfect (1.0) F1 score reflects overly clean/separable synthetic attack classes, not real-world detection difficulty. See `REPORT.md` Lab 4 for full analysis.
- The sequence model (“GRU” script) is actually a rolling-window MLP per the tool’s own metadata output, and it failed to learn any attack class in this run, defaulting to predicting Benign for nearly all inputs.
- The streaming detector’s confidence scoring is rule-based and additive, not a calibrated probability — threshold tuning behaves unpredictably (see `REPORT.md` Lab 8).
- All results are based on synthetic data only. No model in this project has been validated against real or public benchmark network traffic (e.g., CIC-IDS2017/CSE-CIC-IDS2018).
- The response simulator is a lab-only decision-support tool, not a production SOAR system, and must never be connected to real network control planes.

## Safety and Legal Boundary

This project is strictly defensive and was executed only on synthetic, locally-generated lab data. No real systems, credentials, malware, or unauthorized scanning were involved. All response/containment actions remain in simulated dry-run mode, requiring explicit human approval — consistent with the course’s safety and legal requirements.

## Author

Paul — AI-Driven Cybersecurity and Digital Forensics Fellowship, ICDFA