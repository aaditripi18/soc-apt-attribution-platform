# Lab recording guide — producing calibration recordings safely

**Why this exists.** Corpus v2 is built from real recorded emulations, and the fitting-readiness gate (doc 15
DC-5) says what is still missing. Public recordings supply only two actors (APT29, held back for the blind test,
and APT3). Calibration needs **at least 4 actors, 12 calibration and 8 held-out scenario families, and hard
negatives (≥ 3 / ≥ 2, each with ≥ 2 observed techniques)** — see
`data/calibration/corpus/v2/build/readiness-report.json`. This guide describes how to record the missing
material so the platform can ingest, label and gate it with no manual editing.

## 1. Safety rules (non-negotiable — doc 12 §J)

- **Never run adversary emulation on the development host** (the machine this repository lives on). Emulation
  executes real, benign-but-real attack behaviour.
- Use **disposable virtual machines** on an **isolated internal network**: host-only / internal switch, no bridge
  to your home or work LAN, no route to the internet. If a plan needs a command-and-control server, it runs on a
  VM inside the same isolated network.
- Take a **clean snapshot** of every VM before a run and **revert** after it.
- Use **lab-only accounts and passwords**. Never sign in to personal or real accounts inside the lab.
- The **only** things that leave the lab are text: the exported log archive, the emulation report and the run sheet
  (§6). Never copy tools, payloads or binaries out.
- On the platform side, recordings are **inert data**: they are read, never executed (`scripts/check_recording.py`
  and the recording pipeline stream archives without extracting them).

## 2. Lab layout

| VM | Role | Notes |
|---|---|---|
| Emulation server | Runs MITRE CALDERA (Linux) | Isolated network only |
| Workstation 1, 2 | Windows 10/11 victims | Telemetry sources (§3) |
| Domain controller (recommended) | Windows Server | Many plans use Active Directory steps |

A hypervisor you already have (Hyper-V, VirtualBox or VMware) is fine. Keep **all VM clocks synchronized** to one
time source inside the lab, and note each VM's time zone.

## 3. Telemetry configuration (every Windows VM)

The platform supports Sysmon, Windows Security and PowerShell/Operational (ADR-0008). Configure all three:

1. **Sysmon** (Microsoft Sysinternals) with a published configuration that logs at least process creation (1),
   process termination (5, required for PowerShell process identity — ADR-0003 Amendment B), network (3), image
   load (7), remote thread (8), process access (10), file create (11), registry (12/13), pipes (17/18), WMI
   (19–21), DNS (22) and file delete (23). OTRF's configuration used for the APT29 datasets
   (`OTRF/Blacksmith`, `resources/configs/sysmon/`) is a good reference.
2. **Windows Security auditing**: advanced audit policy for process creation (4688, with command line), logon
   (4624/4776), object access (4656/4663/4658 with SACLs), file share (5140/5145). OTRF's
   `Enable-WinAuditCategories.ps1` (`OTRF/Blacksmith`) documents the categories its datasets used.
3. **PowerShell logging**: module logging (4103) and script-block logging (4104), via Group Policy.
4. **Collection**: Winlogbeat 8.x on each VM (or on a Windows Event Forwarding collector) reading the channels
   `Microsoft-Windows-Sysmon/Operational`, `Security` and `Microsoft-Windows-PowerShell/Operational`, writing
   **JSON lines to a local file** (Winlogbeat's file output). The adapters read these `winlog` collector records
   directly (also Winlogbeat 6 and flat NXLog exports).

Record the Sysmon configuration's SHA-256, the audit-policy source and the Winlogbeat version for the run sheet.

## 4. What to record

- **Actors (calibration / held-out).** Run officially published emulation plans for actors **not** already in the
  corpus — e.g. the MITRE Engenuity CTID Adversary Emulation Library plans for **FIN6, menuPass, OilRig, Wizard
  Spider, Sandworm, Carbanak / FIN7** (already pinned in `data/emulation-plans/ctid/`). Use CALDERA's supported
  way of running them (see the CALDERA and CTID library documentation for your version). **Run the plans as
  published; do not modify their steps** — the published plan is the label's provenance.
- **How many.** Aim for **≥ 3 new actors × ≥ 5 runs each** (a run = one plan scenario, from a fresh snapshot;
  vary the victim host or phase between runs). With APT3 that gives the ≥ 4 actors and ≥ 20 families the gate
  needs, and lets whole families be split between calibration and held-out.
- **Hard negatives.** Run the CTID **micro emulation plans** (behaviours shared by many actors — AD enumeration,
  log clearing, named pipes, process injection, …; READMEs pinned in `data/emulation-plans/ctid/micro_emulation_plans/`).
  Each needs **≥ 2 observed techniques** to count as *hard*.
- **Optional: benign baseline sessions** (ordinary admin work, no emulation) — useful background.

## 5. During a run

1. Revert all VMs to their clean snapshots; confirm Sysmon, auditing, PowerShell logging and Winlogbeat are running.
2. Note the start time (UTC).
3. Run exactly one plan scenario.
4. Note the end time (UTC); wait a minute for logging to flush; stop Winlogbeat.

## 6. What to export per run (all text)

1. **Log archive** — the Winlogbeat JSON-lines file(s) from every VM, zipped together:
   `<actor>-<plan>-<run>.zip`.
2. **Emulation report** — CALDERA's exported operation report (JSON) for the run: which steps executed, on which
   host, when. This is the documented procedure actually executed and is what the units will be labelled from.
3. **Run sheet** (a short text/JSON file): actor, plan name and version/commit, CALDERA version, hosts, start/end
   (UTC), time zones, Sysmon config SHA-256, audit-policy source, Winlogbeat version, and any step that failed.

## 7. Intake on the platform

1. Copy the three files to `data/cache/lab/<actor>/` (git-ignored; never inside the lab).
2. Run the intake check:

   ```bash
   python scripts/check_recording.py data/cache/lab/<actor>/<file>.zip --json data/cache/lab/<actor>/<file>.check.json
   ```

   **Problems** (unreadable lines, a host without Sysmon, records without a host, nothing converted) block use;
   fix the collection and re-run. **Warnings** (missing Security or PowerShell on a host, collector clock gaps,
   adapter refusals) are recorded and reviewed.
3. Hand over the archive, report, run sheet and check result. The recording is then pinned (SHA-256) in
   `data/calibration/corpus/v2/recordings.json`, its units inventoried (`scripts/inventory_corpus_units.py`),
   labelled from the emulation report (a report-driven labelling rule is added and tested on the first real
   report — its format is verified on real exports, not assumed), and the corpus rebuilt and gated
   (`scripts/build_corpus_v2.py`).

## 8. After each run

Revert every VM to its clean snapshot. Keep only the three exported text files.
