# ForensicGraph AI Investigation Workbench

**AICS-110 — AI-Enhanced Digital Forensics**
*ICDFA AI-Driven Cybersecurity and Digital Forensics Fellowship*

## Overview

This repository documents the build, execution, and examiner-grade validation of the **ForensicGraph AI Investigation Workbench** — a Linux-based, AI-assisted digital forensics pipeline built as the capstone project for AICS-110. The workbench takes raw case evidence (a conversation log, browser history, download log, and network log) and processes it through eight stages: entity extraction, knowledge graph reconstruction, STIX-style indicator generation, browser-history profiling, timeline fusion, evidence-backed question answering (RAG), and final report generation.

The project is built around the CKIM2024 AI4Forensics lab theme: **AI accelerates forensic analysis, but every AI output is treated as a lead requiring examiner validation — never as a final finding.**

## Project Objective

- Extract forensic entities (IPs, URLs, domains, filenames, hashes, emails, timestamps) from evidence narratives using AI-assisted tooling.
- Reconstruct a knowledge graph linking entities, artifacts, sources, and timelines.
- Generate STIX-style indicators to demonstrate structured threat-intelligence sharing.
- Profile browser-history activity using evidence-supported categories, without unsupported psychological or legal conclusions.
- Build a local, evidence-backed retrieval assistant (RAG) that answers case questions with file references.
- Manually validate every AI-generated output against primary source evidence, and document where the AI was wrong, incomplete, or misleading.
- Produce a defensible, examiner-grade forensic report with documented chain of custody, limitations, and conclusions.

## Scenario

The investigator is assigned a **synthetic, training-only phishing incident** (`case_alpha`). A user reports receiving an urgent “account verification” email from `support@banksecure.com`, containing a link to `http://banksecure-verification.com/login`. The user clicked the link but did not enter credentials, later found a file called `AccountDetails.exe` in their Downloads folder, and the team plans to hash the file, preserve browser history, correlate DNS/HTTP logs, reset passwords, and document chain of custody. The investigator’s task is to process this evidence end-to-end using the workbench, validate every AI-generated finding against the source data, and produce a defensible examiner report.

All evidence in this project is synthetic training data. No real persons, systems, or live evidence are involved.

## Repository Structure

```
AICS110/
└── ForensicGraphAI_Project/
    ├── data/case_alpha/          # Source evidence files
    ├── scripts/                  # Pipeline scripts (Labs 1-8)
    ├── outputs/case_alpha/       # Generated outputs (entities, graph, STIX, timeline, etc.)
    ├── setup_linux.sh
    └── requirements.txt
README.md                         # This file
report.md                         # Full lab-by-lab procedure, outputs, and findings
```

## Environment

|Item  |Value                                               |
|------|----------------------------------------------------|
|OS    |Ubuntu 24.04.3 LTS (noble), VMware Workstation VM   |
|Python|3.12.3                                              |
|Mode  |Offline, deterministic pipeline (no cloud LLM calls)|

## Table of Contents — `report.md`

1. [Environment Setup](report.md#1-environment-setup)
1. [Lab 1 — Environment and Case Creation](report.md#2-lab-1--environment-and-case-creation)
1. [Lab 2 — Evidence Entity Extraction](report.md#3-lab-2--evidence-entity-extraction)
1. [Lab 3 — Forensic Knowledge Graph Reconstruction](report.md#4-lab-3--forensic-knowledge-graph-reconstruction)
1. [Lab 4 — STIX-Style Evidence Modelling](report.md#5-lab-4--stix-style-evidence-modelling)
1. [Lab 5 — Browser History AI-Assisted Profiling](report.md#6-lab-5--browser-history-ai-assisted-profiling)
1. [Lab 6 — Timeline Fusion](report.md#7-lab-6--timeline-fusion)
1. [Lab 7 — Local Forensic Retrieval Assistant (RAG)](report.md#8-lab-7--local-forensic-retrieval-assistant-rag)
1. [Lab 8 — Final Report Generation](report.md#9-lab-8--final-report-generation)
1. [Validation and Corroboration](report.md#10-validation-and-corroboration)
1. [Limitations and Uncertainty](report.md#11-limitations-and-uncertainty)
1. [Recommendations](report.md#12-recommendations)
1. [Conclusion](report.md#13-conclusion)
1. [Findings Table](report.md#14-findings-table)
1. [Appendix — Full Command Reference](report.md#15-appendix--full-command-reference)

## Safety and Ethics Notes

- All evidence used is authorized training data only.
- No real people were investigated or profiled.
- No sensitive or personal data was uploaded to any external/cloud AI service.
- Every AI-generated finding in `report.md` was manually cross-checked against primary source evidence before being accepted.

## License / Attribution

Built for the ICDFA AI-Driven Cybersecurity and Digital Forensics Fellowship, AICS-110, based on the CKIM2024 AI4Forensics lab theme (Apache License 2.0 upstream reference).
