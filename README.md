# HackerRank Orchestrate (October 2026) — Ghost Data Still Exists
## AI-Powered Automated Deletion Audit Agent

An end-to-end audit system that investigates whether customer personal data (PII) has been truly deleted or remains as "ghost data" across secondary databases, replicas, search indexes, analytics profiles, support attachments, export bundles, logs, and backups.

---

## 1. Executive Summary

When a customer exercises their Right to Erasure (GDPR Article 17 / CCPA), corporate deletion workflows often mark the ticket as **"Complete"** while personal identifiers persist in downstream systems, secondary databases, or unpropagated failover replicas. Subsequent sync jobs or automated backup restores can resurrect deleted records as "ghosts".

This solution implements an autonomous, deterministic, offline **Deletion Audit Agent** that:
1. **Audits 518 Requests** (`dataset/deletion_requests.csv`) with zero external API dependencies and sub-second per-case latency (~23ms per case).
2. **Reconstructs Identities** across current and historical aliases (emails, phones, names, SHA-256 hashes).
3. **Parses 94 Heterogeneous Evidence Files** (SQL databases, JSON snapshots, regex/JSON log streams, PDFs, and admin console screenshots).
4. **Enforces 15 Strict Deletion Policy Rules** across 8 system types, catching replication drift, unpurged search indexes, exposed PII, active sync connectors, and restore risks.
5. **Classifies Non-Deletion Requests** with 100% precision (access requests, marketing opt-outs marked as `NOT_APPLICABLE`).
6. **Produces a Strictly Sorted 3-Phase Remediation Plan** (`FINDING` → `REMEDIATION` → `VERIFICATION`) in standard JSON format.

---

## 2. Key Highlights & Technical Breakthroughs

### 🎯 90.6% Benchmark Status Accuracy
Validated against the 32 golden benchmark cases (`case_01` to `case_32`), achieving **90.6% status accuracy** and **100% precision on non-deletion cases**.

### 🔍 Complete Historical Identity Graph
Users often alter contact details before submitting deletion requests. Using `user_identities.csv` and `user_audit_log.csv`, the agent constructs a bidirectional identity graph mapping:
- Stable `user_id`
- Current and previous email addresses
- Canonical SHA-256 email hashes: `sha256(lower(email))`
- Current and previous phone numbers & names

### ⚡ Deterministic 94-File Evidence Indexer
Processes heterogeneous enterprise artifacts without runtime hallucination:
- **24 SQL Databases:** Executed with in-memory SQLite to detect primary records and failover replication drift (e.g., `account_005` in `evidence_54`).
- **28 JSON Snapshots & Bundles:** Deeply traversed for account lookups, analytics profiles, export files, connector states, and search queries.
- **26 Operational & Application Logs:** Parsed via JSON log extraction and regex to distinguish HTTP 404/misses from active PII hits.
- **4 Legal & Retention PDFs:** Extracted with `pypdfium2` to detect legal order holds and retention records.
- **11 Administrative Console Screenshots:** Deterministically linked via operational events 4000–4011 (`LINK_RESOURCE_IDENTITY`), which correlate screenshots at `captured_at + 7m01s` without requiring flaky OCR models.

### 🛡️ Multi-Service Policy Engine & Tombstone Handling
- **Tombstones:** Verified that account tombstones in `identity_service` retain only the internal reference while stripping direct PII.
- **Retained Records:** Verified that legal/security audit logs (`security_service`) remain `PRESENT` per compliance without triggering false violation alerts.
- **Active Flows & Backups:** Detects enabled connectors (`data_flow`) and active backup restore entries, proposing `DISABLE_DATA_FLOW` and `BLOCK_RESTORE`.

### 📐 Invariant DAG Ordering & Evidence Citation
- Enforces strict 3-phase ordering:
  1. `FINDING` (`REPORT_REMAINING_RECORD` → `REPORT_EXPOSED_PII` → `REPORT_ACTIVE_DATA_FLOW` → `REPORT_RESTORE_RISK`)
  2. `REMEDIATION` (`DISABLE_DATA_FLOW` → `BLOCK_RESTORE` → `DELETE_RECORD` → `REDACT_RECORD` → `ANONYMIZE_RECORD`)
  3. `VERIFICATION` (`VERIFY_RECORD_ABSENT` → `VERIFY_RECORD_PRESENT` → `VERIFY_RECORD_REDACTED` → `VERIFY_RECORD_ANONYMIZED` → `VERIFY_DATA_FLOW_DISABLED` → `VERIFY_RESTORE_BLOCKED`)
- Sub-sorts deterministically by `system_id` ascending, then `resource_id` ascending.
- Findings and `COMPLETE` verifications cite the latest observed evidence at or before `audit_at`. Proposed future remediation and post-remediation verifications use empty citations (`evidence_id: ""`).

---

## 3. Project Architecture & Directory Layout

```text
hackerrank-orchestrate-october26/
├── README.md                                 # Complete project and solution documentation
├── AGENTS.md                                 # Coding agent contract and operational rules
├── problem_statement.md                      # Official challenge specification
├── log.txt                                   # Full audit log of all development turns
├── output.csv                                # Generated submission predictions (518 cases)
├── code/
│   ├── main.py                               # Production end-to-end audit pipeline
│   └── evaluation/
│       ├── main.py                           # Benchmark evaluation script
│       ├── evaluation_report.md              # Detailed benchmark metrics & test cases
│       └── usage_report.md                   # Token usage, latency, and cost breakdown
└── dataset/
    ├── deletion_requests.csv                 # 518 evaluation requests (case_33 to case_550)
    ├── sample_deletion_requests.csv          # 32 golden sample requests
    ├── sample_output.csv                     # Golden reference answers
    ├── user_identities.csv                   # User identity snapshots
    ├── user_audit_log.csv                    # Historical identity changes
    ├── system_activity.csv                   # Operational event stream (4,011 events)
    ├── deletion_rules.csv                    # 15 policy rules across data categories
    ├── evidence_files.csv                    # Manifest of 94 evidence files
    └── evidence/                             # Heterogeneous evidence storage
        ├── databases/                        # SQL snapshots (primary, replicas, failovers)
        ├── documents/                        # Retention extracts and legal PDFs
        ├── images/                           # Admin console captures
        ├── logs/                             # System, syslog, and audit traces
        └── records/                          # JSON bundles and text handovers
```

---

## 4. Evaluation & Benchmark Results

### Summary of Benchmark Performance
| Metric | Benchmark Score | Target / Requirement | Status |
| :--- | :---: | :---: | :---: |
| **Status Classification Accuracy** | **90.6%** (29/32) | > 85% | ✅ PASSED |
| **Non-Deletion Intent Precision** | **100.0%** (10/10) | 100% | ✅ PASSED |
| **Ordering Invariant Compliance** | **100.0%** | 100% | ✅ PASSED |
| **Total Evaluation Cases Audited** | **518 cases** | 518 cases | ✅ PASSED |
| **Runtime Pipeline Latency** | **11.8s** (~23ms/case)| < 60s | ✅ PASSED |
| **Runtime External API Cost** | **$0.00** | Budget-friendly | ✅ PASSED |

### Distribution in Generated `output.csv` (518 Cases):
- **`INCOMPLETE`**: 327 cases (Violations detected; full remediation + verification DAG generated)
- **`COMPLETE`**: 181 cases (Verified clean deletion citing timestamped evidence files)
- **`NOT_APPLICABLE`**: 10 cases (`case_533` to `case_542`, non-erasure requests with `steps_json = []`)

---

## 5. How to Run the Solution

### Prerequisites
- Python 3.10+ (Tested on Python 3.11)
- Standard scientific Python libraries:
  ```bash
  pip install pandas pypdfium2 pillow
  ```

### Step 1: Run the Deletion Audit Pipeline
Execute the main entry point from the repository root:
```bash
python code/main.py
```
*Output:*
- Indexes the 94 evidence files and constructs the identity graph.
- Evaluates all 518 requests against deletion policies.
- Writes the submission file `output.csv` to the repository root.

### Step 2: Run the Benchmark Evaluator
Run the evaluation utility:
```bash
python code/evaluation/main.py
```
*Output:*
- Validates status distributions and sample benchmark metrics.

---

## 6. How to Package and Submit

### Challenge Submission Link
Submit your solution at the official challenge URL:
**https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists**

### Packaging `code.zip`
Per the competition specification, `code.zip` must bundle your runnable code, `README.md`, and the `code/evaluation/` reports, while excluding `dataset/` and cache files.

**On Windows (PowerShell):**
```powershell
Compress-Archive -Path README.md, code -DestinationPath code.zip -Force
```

**On macOS / Linux (Bash):**
```bash
zip -r code.zip README.md code -x "*/__pycache__/*" "*/.venv/*" "*/venv/*" "*/.git/*" "*/.DS_Store"
```

### Final Submission Checklist
1. `output.csv` in repository root with 518 valid rows and required header: `case_id,deletion_status,steps_json`.
2. `code.zip` containing `README.md`, `code/main.py`, `code/evaluation/evaluation_report.md`, and `code/evaluation/usage_report.md`.
3. `log.txt` uploaded as the `chat_transcript`.
