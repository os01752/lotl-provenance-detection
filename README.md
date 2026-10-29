# Behaviour-Based Detection of Living-off-the-Land Attacks via Process-Provenance Telemetry

IT 7178 semester research project (progress report) — Olaoluwa E. Sipeolu, Georgia Southern University.

Living-off-the-Land (LotL) attacks abuse trusted system binaries (bash, curl, crontab, …),
so they cannot be caught by binary name alone. This project captures Linux `auditd`
process-execution telemetry, reconstructs **process-provenance graphs** (parent→child
lineage), extracts behavioural features, and shows that a provenance-aware behaviour score
separates malicious LotL activity from benign administrative use of the **same** binaries —
where a naive name-based detector raises false positives.

## Repository layout
```
├── LotL_Provenance_Detection.ipynb   # Colab/Jupyter notebook — run this
├── src/provenance.py                 # parser, graph builder, feature extractor
├── capture/
│   ├── lotl.rules                     # auditd execve rules
│   └── capture.sh                     # per-activity capture harness
├── captures/                         # put your 8 .log files here (see its README)
├── report/
│   ├── main.tex                       # IEEE-format report (Overleaf)
│   └── references.bib                 # 20+ IEEE/ACM references
└── requirements.txt
```

## How the data was collected
A Ubuntu Server (ARM64) UTM VM captures every `execve`/`execveat` syscall via `auditd`.
`capture/capture.sh` runs each labelled activity and saves its audit records to
`captures/<label>.log`. Benign captures are routine admin tasks; malicious captures emulate
LotL techniques mapped to MITRE ATT&CK (T1059.004, T1105, T1053.003), executed safely in
the VM.

## How to reproduce the analysis
1. Put the 8 `.log` files in `captures/` (see `captures/README.md`).
2. Open `LotL_Provenance_Detection.ipynb` in Google Colab (or Jupyter).
3. In the first cell, set `REPO` to this repository's clone URL.
4. Run all cells. Outputs: feature table, provenance-graph figure, detection
   comparison (name-based baseline vs. provenance score), and per-capture score chart.
5. `File → Print → Save as PDF` to produce the executed-notebook PDF deliverable.

## Methods
- **Telemetry:** Linux `auditd` execve/execveat records.
- **Graphs:** `networkx` DiGraph per activity; nodes = processes, edges = parent→child.
- **Features:** chain depth, shell-spawns-shell, LotL-binary usage, command-line length &
  Shannon entropy, and behavioural indicators (base64→shell, hidden-path payload,
  chmod +x of a download, persistence install).
- **Detectors:** name-based baseline vs. transparent provenance behaviour score.
