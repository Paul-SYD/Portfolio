# ThreatFusion AI — Defensive Cyber Threat Intelligence Fusion Pipeline

**A capstone project for the ICDFA AI-Driven Cybersecurity and Digital Forensics Fellowship (AICS-107)**

> ⚠️ **Defensive training project only.** All data in this project is synthetic and safe. No real malicious URLs were visited, no malware samples were downloaded, and no intelligence produced here was used against any real system.

-----

## Table of Contents

- [Overview](#overview)
- [Project Objectives](#project-objectives)
- [Scenario](#scenario)
- [Architecture](#architecture)
- [Priority Intelligence Requirements](#priority-intelligence-requirements)
- [What’s in This Repo](#whats-in-this-repo)
- [Full Report](#full-report)

-----

## Overview

ThreatFusion AI is a defensive CTI (Cyber Threat Intelligence) fusion pipeline that takes raw threat reports and turns them into structured, actionable intelligence. It performs IOC extraction, ATT&CK technique mapping via a trained classifier, knowledge graph construction, organization-weighted risk scoring, STIX 2.1 export for platform sharing, and audience-specific analyst report generation — all run through a single CLI tool (`threatfusion_ai.cli`) against a synthetic, safe dataset of 61 CTI reports.

## Project Objectives

- Build an end-to-end pipeline that turns unstructured CTI reports into structured, machine-readable intelligence
- Train and evaluate a model capable of mapping report content to MITRE ATT&CK techniques
- Reveal relationships between reports, indicators, and techniques through a knowledge graph
- Score and prioritize intelligence according to a specific organization’s actual risk priorities, not generic defaults
- Produce intelligence in a format (STIX 2.1) that real CTI platforms like MISP and OpenCTI can consume
- Communicate findings appropriately to both executive and technical audiences

## Scenario

All analysis is framed around a fictional organization: **Zenport Microfinance Bank**, a mid-size Nigerian digital-first microfinance bank. Framing the project around a specific organization type is what turns raw IOC extraction into actual *intelligence* — every requirement, scoring decision, and recommendation in this project is written to support decisions this bank’s SOC team would realistically need to make.

## Architecture

|Stage     |Module            |Function                                                                   |
|----------|------------------|---------------------------------------------------------------------------|
|Ingestion |`init-data`       |Generates synthetic CTI reports → `data/raw/`                              |
|Extraction|`run-pipeline`    |Parses report text, extracts structured IOCs → `data/processed/`           |
|Modeling  |`train`           |Trains a multi-label classifier mapping report text → ATT&CK techniques    |
|Graphing  |`run-pipeline`    |Builds a knowledge graph of cases, techniques, and IOCs → `outputs/graphs/`|
|Scoring   |`scoring.py`      |Computes a numeric risk score and severity band per case                   |
|Export    |`run-pipeline`    |Converts enriched cases into a STIX 2.1-style bundle → `outputs/stix/`     |
|Reporting |`report --case-id`|Generates Markdown analyst reports → `outputs/reports/`                    |

## Priority Intelligence Requirements

Three PIRs anchor the entire project to real SOC decisions rather than abstract data analysis:

1. **Credential and Account Takeover Threats** — informing MFA and credential-monitoring priorities
1. **Ransomware Targeting Financial Services** — informing backup/recovery and IR planning
1. **Command-and-Control and Exfiltration Infrastructure** — informing network egress detection rules

Full requirement text, scope, and decision linkage is in [REPORT.md](./REPORT.md#priority-intelligence-requirements).

## What’s in This Repo

- **`README.md`** — this file: project overview and orientation
- **`REPORT.md`** — the full methodology, step-by-step walkthrough, commands run, bugs encountered and fixed, model evaluation, risk scoring changes, STIX export, analyst reports, key findings, recommendations, limitations, future work, and safety/ethics notes

## Full Report

The complete step-by-step methodology — every command run, every output, every fix applied along the way, plus findings and recommendations — is documented in **[REPORT.md](./REPORT.md)**.

-----

*Built as part of the ICDFA AI-Driven Cybersecurity and Digital Forensics Fellowship (AICS-107). For authorized defensive training purposes only.*
