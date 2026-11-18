# Quick chunk runs — preliminary results for discussion

Date: 2026-11-18

Status: **exploratory, small chunks only — not paper-ready.** Two configurations were run on the same 8-sample balanced chunk. RAG configurations were not run (no Qdrant index/processed knowledge exists in this working tree).

## Setup

- Runtime: Ollama reachable, `mistral` available; Semgrep 1.180.0; Python 3.13.5.
- Dataset: `data/benchmark/paper_chunk.jsonl` (PrimeVul, `split=paper`, 12 labelled samples, 6 vulnerable / 6 benign).
- Selection: `select_pilot(limit=8, seed=42, stratify=True)` → 4 vulnerable + 4 benign.
- Sample IDs: `primevul:226178` (0), `primevul:204278` (1), `primevul:416360` (0), `primevul:202600` (1), `primevul:229316` (0), `primevul:200831` (1), `primevul:195083` (1), `primevul:498134` (0).
- Fixed settings: temperature 0, decision threshold 0.5, prompt `v1`, all 8 predictions successful in both runs.

## Results

| Metric | `llm_only` (run `357d68222abe`) | `llm_sast` (run `f8ff5a160197`) |
|---|---:|---:|
| n (vuln / benign) | 8 (4 / 4) | 8 (4 / 4) |
| TP / FP / TN / FN | 1 / 0 / 4 / 3 | 0 / 0 / 4 / 4 |
| Precision | 1.000 | undefined (no positive predictions) |
| Recall | 0.250 | 0.000 |
| F1 | 0.400 | 0.000 |
| Accuracy | 0.625 | 0.500 |
| Balanced accuracy | 0.625 | 0.500 |
| Specificity | 1.000 | 1.000 |
| False-positive rate | 0.000 | 0.000 |
| MCC | 0.378 | 0.000 |
| Brier | 0.314 | 0.410 |
| ECE (10 equal-width bins) | 0.313 | 0.400 |
| AUROC | 0.625 | 0.500 |
| AUPRC | 0.625 | 0.500 |
| VD-S (target FPR 0.5%) | 0.750 (achieved FPR 0.0, threshold 0.8) | 1.000 (achieved FPR 0.0, threshold 0.1) |
| Mean latency (s) | 37.34 | 12.38 |
| Median / p90 / p95 latency (s) | 40.59 / 50.17 / 53.56 | 12.48 / 14.36 / 15.29 |
| Successful inference | 8/8 | 8/8 |
| Scanner failure rate | 0.0 | 0.0 |
| Retrieval failure rate | 0.0 | 0.0 |

All scores are **uncalibrated** `p_vulnerable`; no post-hoc calibration was applied (that belongs on the validation split).

## Observations

1. `llm_only` showed weak but non-zero signal on this chunk: 1 of 4 vulnerable samples was flagged, with no false positives (AUPRC 0.625, MCC 0.378).
2. `llm_sast` produced no positive predictions at all; all eight scores were `p_vulnerable = 0.1`, giving the degenerate no-signal values (AUPRC 0.5, VD-S 1.0).
3. The cause is not scan errors: scanner failure rate was 0%. A direct check with `scan_code()` confirmed the bundled `configs/semgrep.yml` returned **0 findings on all 8 samples**. The tiny research ruleset contributed no evidence to the prompt.
4. `llm_sast` was much faster (12.4 s vs 37.3 s mean), but that reflects shorter model outputs on the degenerate all-0.1 responses, not a genuine efficiency gain.
5. VD-S and AUPRC on n=8 are extremely coarse; the note in the exported metrics still says "at n=10" (hard-coded string) — treat these numbers as directional only.

## Discussion points / next steps

- Strengthen the Semgrep ruleset (or verify language/extension handling) before treating "SAST adds nothing" as a finding; this chunk only shows the current ruleset yields no findings on these C/C++ snippets.
- Inspect the one true positive from `llm_only` and the three misses for qualitative error patterns.
- Run the same 8-sample chunk on the 100-sample validation set (`results/pilot/manifests/`) for calibration experiments, keeping this test chunk held out.
- To exercise RAG configs, restore `data/raw/{nvd,cwe,capec}` symlinks and run `knowledge normalize` + `knowledge build-index` first.

## Artifacts

- CLI outputs: `results/exports/357d68222abe.{jsonl,csv,metrics.json}` and `results/exports/f8ff5a160197.{jsonl,csv,metrics.json}`
- Source of truth: `results/experiments.sqlite`
- Summaries: `results/summaries/latest.json`

---

## Post-fix rerun (supersedes the results above)

Date: 2026-11-18. Prompt `v3`, new C/C++ Semgrep ruleset, constant-score guard, working checkout made authoritative for imports. Same 8 samples, `--force`, no cached predictions.

| Metric | `llm_only` (`bdffbf02fdc9`) | `llm_sast` (`4644f209028b`) |
|---|---:|---:|
| TP / FP / TN / FN | 2 / 0 / 4 / 2 | 2 / 0 / 4 / 2 |
| Precision | 1.000 | 1.000 |
| Recall | 0.500 | 0.500 |
| F1 | 0.667 | 0.667 |
| Accuracy / balanced accuracy | 0.750 / 0.750 | 0.750 / 0.750 |
| MCC | 0.577 | 0.577 |
| Brier / ECE | 0.201 / 0.188 | 0.198 / 0.225 |
| AUROC / AUPRC | 0.875 / 0.875 | 0.906 / 0.893 |
| Scanner failures | 0 | 0 |
| Degenerate constant scores | none | none |
| Suitable for paper | **No** (pilot n=8; requires ≥100) | **No** (pilot n=8; requires ≥100) |

Score distributions are now varied: `llm_only` 0.2×5, 0.3×1, 0.6×2; `llm_sast` 0.1×1, 0.2×4, 0.3×1, 0.6×2. The earlier all-0.1 collapse is gone.

The new `configs/semgrep.yml` includes vetted C rules from Semgrep's `p/security-audit` pack plus local high-signal C/C++ patterns. It still yields 0 findings on these 8 specific snippets, but it produced findings on 2 of the first 30 validation samples (and scan parse failures are still retained as failures, not "clean"). Crucially, with the prompt fixed, an empty scan no longer suppresses a correct vulnerability judgment.

All 36 unit tests pass. RAG configs now fail fast with a clear message until a Qdrant index is built, instead of silently recording retrieval errors.
