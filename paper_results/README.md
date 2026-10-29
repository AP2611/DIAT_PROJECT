# PrimeVul 10-sample pilot results

**Status: not ready to proceed to a larger run.** This exploratory pilot used the official PrimeVul test split, with 5 vulnerable and 5 benign samples selected by stratified sampling (seed 42). Both systems missed all 5 vulnerable samples. The sample is too small for paper claims, and VD-S at 0.5% FPR is especially coarse here.

| Metric | LLM | LLM + SAST |
|---|---:|---:|
| Precision | undefined (no positive predictions) | undefined (no positive predictions) |
| Recall | 0.000 | 0.000 |
| F1 score | 0.000 | 0.000 |
| AUPRC / PR-AUC | 0.500 | 0.500 |
| MCC | 0.000 | 0.000 |
| Balanced accuracy | 0.500 | 0.500 |
| VD-S (FPR ≤ 0.5%) | 1.000 | 1.000 |
| False-positive rate | 0.000 | 0.000 |
| Specificity | 1.000 | 1.000 |
| Accuracy | 0.500 | 0.500 |

| Confusion matrix | LLM | LLM + SAST |
|---|---:|---:|
| TP | 0 | 0 |
| FP | 0 | 0 |
| TN | 5 | 5 |
| FN | 5 | 5 |

LLM+SAST had 10/10 completed LLM predictions, but Semgrep reported scan errors for 3 samples (two partial parses and one syntax error). Those scan errors were retained as failures and not treated as clean scans. Scanner failure rate: 30%.

All ten model scores were tied at `p_vulnerable = 0.1`, so both systems made all-benign decisions at the configured 0.5 threshold. Precision is undefined because neither system predicted a positive; F1 and MCC are reported as 0 for the no-signal case. AUPRC is 0.5 for tied scores. VD-S is 1.0 at achieved FPR 0.0 with no samples predicted vulnerable, illustrating the coarse operating point at n=10.

The full requested metrics, run metadata, scanner errors, canonicalized input, and per-sample predictions are in this folder.
