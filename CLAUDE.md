# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

SOC APT Attribution Platform — a personal cybersecurity research and portfolio project. The goal is an end-to-end system that analyzes security telemetry, identifies observable adversary behavior, maps evidence to MITRE ATT&CK techniques/sub-techniques, correlates related activity, reconstructs attack chains, and performs explainable, evidence-based APT attribution.

This is not a commercial product — do not over-engineer for enterprise requirements — but technical quality, correctness, architecture, and presentation must be exceptional. Demonstrate serious cybersecurity engineering, not a dashboard with a good-looking frontend.

## Current State

The platform is **complete and validated**: detection, correlation, attribution, live mode, the analyst console, the Kibana dashboard and a hosted read-only demo are built, tested and documented (see [README.md](README.md) and the ADRs under `docs/architecture/adr`).

- Work now consists of maintenance and incremental, evidence-driven improvements.
- Any change to detection, correlation or attribution logic follows the Development Philosophy below and is recorded in an ADR.
- Published validation results under `data/validation` are regenerated, never hand-edited; earlier runs stay published beside new ones.
- The guidance below was written at the project's start and still governs every change.

## Lessons from the Previous Version (do not repeat)

A prior version of this project had a strong frontend but failed on the underlying cybersecurity functionality:

- unreliable MITRE ATT&CK technique mapping
- weak relationships between telemetry and techniques
- poor APT attribution logic
- hard-coded or simulated results
- weak data modeling
- disconnected backend functionality
- frontend features not backed by real functionality

Backend, data, detection, correlation, and attribution foundations must be built and validated before frontend polish becomes a priority.

## Core Principles

1. Never fabricate cybersecurity functionality.
2. Never hard-code attribution results merely to make the interface look impressive.
3. Attribution must be based on observable evidence.
4. Every important attribution conclusion must be explainable.
5. MITRE ATT&CK relationships must be modeled systematically.
6. Security telemetry must have a clear and traceable path through the system.
7. Elastic Stack is a core part of the telemetry and security analytics architecture.
8. Prefer authoritative sources and mature open-source components over manually recreating existing security knowledge.
9. Every major cybersecurity capability must have validation and tests.
10. Frontend functionality must ultimately connect to real backend functionality.
11. Visual polish must never take priority over correctness.
12. Architectural decisions should be documented rather than silently changed.
13. Prefer modular, maintainable components over one large monolithic implementation.
14. Do not introduce unnecessary complexity merely to make the project appear sophisticated.

## Attribution Philosophy

APT attribution must be evidence-driven rather than label-driven. The system should be able to explain:

- what was observed
- what evidence was extracted
- which ATT&CK techniques are supported, and why
- which threat actors/groups are consistent with the evidence, and what evidence supports or contradicts each candidate
- how strong the attribution is, what uncertainty remains, and what additional evidence would improve confidence

Where appropriate, support competing attribution hypotheses instead of assuming a single answer. Confidence scores must have an understandable methodology — never arbitrary numbers displayed by the UI.

## MITRE ATT&CK

Treat ATT&CK as structured threat knowledge, not a list of manually copied technique names. Model relevant relationships between tactics, techniques, sub-techniques, software, groups, procedures, observations, detections, and evidence. ATT&CK data should be versioned or otherwise handled reproducibly so attribution results can be traced to the knowledge version used.

## Elastic Stack

Elastic Stack is a major foundation for telemetry ingestion, normalization, search, detection, correlation, and investigation. Use Elastic capabilities appropriately instead of recreating functionality unnecessarily. Consider ECS alignment wherever appropriate. The exact Elastic architecture must be determined through research before implementation, not assumed prematurely.

## Research Before Implementation

Before making major architectural decisions, investigate:

- Elastic Security capabilities, Elasticsearch, Kibana
- Elastic Common Schema (ECS)
- Elastic detection rules and security content
- Elastic integrations
- MITRE ATT&CK official data and ATT&CK STIX resources
- Sigma and detection-engineering ecosystems
- relevant threat-intelligence frameworks
- existing APT attribution research and tools
- relevant open-source security analytics projects
- relevant datasets and synthetic telemetry sources
- useful graph/correlation technologies

Do not blindly adopt external projects. For each potential dependency or integration, evaluate maturity, maintenance, license, security implications, integration cost, and whether it duplicates functionality Elastic already provides.

## Development Philosophy

Work incrementally. Before implementing a major subsystem:

1. Understand the requirement.
2. Inspect the relevant existing code.
3. Research appropriate technologies when necessary.
4. Document the architectural decision.
5. Implement the smallest sound version.
6. Test it.
7. Validate it with realistic/synthetic cybersecurity scenarios.
8. Only then expand it.

Do not generate the entire application in one step. Do not make large architectural changes without understanding their impact on existing functionality. Do not remove or weaken tests simply to make implementation succeed.

## Frontend

The frontend should eventually provide a polished analyst-oriented experience — potential areas include SOC overview, investigation workspace, incident timeline, ATT&CK technique analysis, attack-chain visualization, evidence analysis, APT attribution, threat actor/campaign analysis, correlation/relationship graphs, IOC investigation, detection analysis, and Elastic telemetry investigation. These are not fixed requirements — refine them after the core system architecture is established. Google Stitch and other UI/UX workflows may be used later for design exploration. Frontend implementation must come after core cybersecurity functionality is sufficiently established.

## Model/Agent Behavior

- Do not assume an architecture without investigation.
- Do not invent APIs, datasets, ATT&CK relationships, or Elastic capabilities when they can be verified.
- Clearly distinguish facts, assumptions, and design decisions.
- If an important technical decision is uncertain, research it before implementing it.
- Reuse mature existing capabilities when appropriate.
- Keep security logic deterministic and testable where possible.
- Prefer explainability over opaque scoring.
- Keep documentation synchronized with significant architectural changes.
