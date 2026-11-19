# Evidence-conditioned LLM vulnerability triage

Research prototype for a DRDO internship experiment:

**Does combining static-analysis evidence with retrieved cybersecurity knowledge improve vulnerability-detection reliability compared with using either source independently? Can evidence-conditioned decisions also support better confidence calibration?**

This repository is a **minimal, reproducible experiment harness**, not a production scanner and not a completed paper. Adding SAST or RAG is **not assumed to help**. Results must be measured.

An exploratory 10-sample PrimeVul test-split pilot was run on 2026-10-29. It is too small for scientific claims; see `paper_results/README.md` and `paper_results/metrics.json`. Do not treat synthetic smoke samples as evidence.

## What is already on this machine

| Resource | Status |
|---|---|
| Ollama | Local service responds; configured `mistral:latest` model is available. |
| Default model | `mistral` (never auto-downloaded) |
| Semgrep | Installed (1.180.0). The 10-sample pilot had scan errors on 3 samples (partial parses / syntax error); see `paper_results/metrics.json`. |
| Embedding model | `sentence-transformers/all-MiniLM-L6-v2` already cached under `~/.cache/huggingface/hub` |
| NVD / CWE / CAPEC | Present outside the repo; **not modified**. `data/raw/{nvd,cwe,capec}` are symlinks to `/Users/arjunpanse/Documents/security-knowledge-base/raw/...` |
| PrimeVul | Official test split present at `PrimeVul_dataset/primevul_test.jsonl`; canonicalized copy used for the pilot is in `paper_results/`. |

Raw files stay immutable. Generated artifacts go to `data/processed/`, `data/qdrant/`, and `results/`.

## Layout

```text
.
├── configs/default.yaml          # model, paths, threshold 0.5
├── configs/semgrep.yml           # small local ruleset for pilots
├── data/raw/                     # symlinks to existing NVD/CWE/CAPEC
├── data/processed/               # normalized knowledge JSONL (generated)
├── data/benchmark/               # canonical JSONL; synthetic smoke included
├── data/qdrant/                  # persistent local Qdrant store
├── src/vulntriage/               # prototype package
├── tests/
├── research/                     # observation template + research log
└── results/                      # SQLite, CSV, JSONL exports
```

## Install

Use the existing Anaconda Python (3.13). Prefer a virtualenv if you want isolation.

```bash
cd /Users/arjunpanse/DIAT_PROJECT
python3 -m pip install -e ".[dev]"
```

Install Semgrep when you want Experiment B/D scanner evidence (optional for LLM-only):

```bash
python3 -m pip install semgrep
```

Start Ollama (PATH on this Mac often omits Homebrew):

```bash
/opt/homebrew/bin/ollama serve
```

Do not pull another model unless you intend to. Confirm `mistral` is listed:

```bash
/opt/homebrew/bin/ollama list
```

## Configuration

Defaults live in `configs/default.yaml`. Environment overrides are in `.env.example`:

- `VULNTRIAGE_OLLAMA_URL` (default `http://localhost:11434`)
- `VULNTRIAGE_OLLAMA_MODEL` (default `mistral`)
- `VULNTRIAGE_NUM_CTX`, `VULNTRIAGE_NUM_PREDICT`
- `VULNTRIAGE_EMBEDDING_MODEL`
- `VULNTRIAGE_SEMGREP_CONFIG`
- `VULNTRIAGE_TOP_K`
- `VULNTRIAGE_DECISION_THRESHOLD` (default `0.5`)
- `VULNTRIAGE_RAW_DATA_DIR`
- `VULNTRIAGE_PROVIDER` (`ollama` or `gemini`; can also be set with `benchmark run --provider`)
- `VULNTRIAGE_GEMINI_MODEL` (default `gemini-3.1-flash-lite`) and `GEMINI_API_KEY` (read from `.env`, never from YAML)

`.env` is loaded automatically at startup and is gitignored. Gemini uses native JSON-schema structured output; all four configs remain identical apart from the evidence source.

Generation temperature is **0**. The binary label is **derived** from `p_vulnerable >= 0.5`, not from the model's free-text label. `decision_confidence = max(p_vulnerable, 1 - p_vulnerable)` is recorded separately and is **not** treated as calibrated confidence.

## Diagnostic

```bash
python -m vulntriage doctor
```

Checks Ollama reachability, whether `mistral` is available, Semgrep, the local embedding cache, and knowledge-file discovery. It never downloads an LLM.

## Commands

```bash
python -m vulntriage doctor

python -m vulntriage knowledge normalize
python -m vulntriage knowledge build-index
python -m vulntriage knowledge search --query "SQL injection"

python -m vulntriage benchmark import --input PATH_TO_DATASET
python -m vulntriage benchmark pilot --limit 20 --seed 42

python -m vulntriage benchmark run --config llm_only --limit 20
python -m vulntriage benchmark run --config llm_sast --limit 20
python -m vulntriage benchmark run --config llm_rag --limit 20
python -m vulntriage benchmark run --config llm_sast_rag --limit 20
python -m vulntriage benchmark run --config all --limit 20

python -m vulntriage benchmark summarize --latest
python -m vulntriage benchmark export --latest
```

`--limit 20` is a **pilot**. Nothing here launches a large experiment by default.

Resume an interrupted run:

```bash
python -m vulntriage benchmark run --config llm_only --limit 20 --resume RUN_ID
```

Force a fresh model call even if a cache key exists:

```bash
python -m vulntriage benchmark run --config llm_only --limit 20 --force
```

Synthetic smoke (not for papers):

```bash
python -m vulntriage benchmark run --config llm_only --limit 3 \
  --dataset data/benchmark/synthetic_smoke.jsonl --include-synthetic
```

## Four experimental configurations

All four use the same samples, the same Mistral model, temperature 0, threshold 0.5, and the same output schema. The only intended difference is evidence:

| Config | Code | Semgrep | Vector RAG |
|---|---|---|---|
| `llm_only` | yes | no | no |
| `llm_sast` | yes | yes | no |
| `llm_rag` | yes | no | yes |
| `llm_sast_rag` | yes | yes | yes |

The model may disagree with Semgrep. Failed scans are recorded as errors and are **never** treated as clean. Ground-truth labels stay in SQLite evaluation records and are not placed in prompts.

## Knowledge / Vector RAG

Pipeline: raw files → `data/processed/documents.jsonl` → local MiniLM embeddings → persistent Qdrant → top-k evidence.

Provenance retained: document id, source, version, CVE/CWE/CAPEC id, title, description, relationships, references.

If a test case has a `cve_id`, that CVE record is excluded from retrieval. Ground-truth CWE labels are not used as queries. Retrieval quality metrics (Precision@k, Recall@k, MRR, nDCG) are **not** reported until labelled qrels exist.

NVD year files are large; normalize them one file at a time (the command already processes files sequentially and prints progress).

If the embedding model is missing locally, load it yourself:

```bash
python -c "from sentence_transformers import SentenceTransformer as S; S('sentence-transformers/all-MiniLM-L6-v2')"
```

The prototype will not silently call a remote embedding API.

## Evaluation dataset

Canonical JSONL fields: `sample_id`, `code`, `label` (1=vulnerable, 0=benign), `source_dataset`, `cwe_id`, `cve_id`, `project_id`, `commit_hash`, `split`, plus provenance.

**PrimeVul** importer maps `func`→`code`, `target`→`label`, `cwe`, `cve`, `project`, `commit_id`, `idx`, `file_name`. Place the official JSONL files on disk and run:

```bash
python -m vulntriage benchmark import --input /path/to/PrimeVul --source primevul
```

Duplicates are dropped; the import report includes class distribution, split counts, and exclusions.

`data/benchmark/synthetic_smoke.jsonl` is **synthetic**, labelled `is_synthetic: true`, and excluded from paper-style summaries unless `--include-synthetic` is passed.

## Tracking and metrics

SQLite at `results/experiments.sqlite` is the source of truth (CSV/JSONL export as well). Each run has a new `run_id`. Predictions are cached by sample + config + model + prompt version + generation settings + index/scanner versions. Previous rows are not overwritten.

When labels exist, the harness computes precision, recall, F1, MCC, accuracy, balanced accuracy, specificity, FPR, confusion matrix, PrimeVul VD-S, Brier, ECE (10 equal-width bins on `[0,1]`), reliability-diagram bins, AUROC/AUPRC when both classes are present, latency percentiles, and success / scanner / retrieval failure rates. Failed samples are kept.

`p_vulnerable` is evaluated as an **uncalibrated** score. Temperature scaling or other calibration belongs on a validation split in a later experiment, never on the final test set.

## Tests

```bash
python -m pytest
```

Core tests mock Ollama and do not need a running LLM or internet.

## Limitations (record these in the paper log)

- The current PrimeVul results are a 10-sample pilot only; both tested configurations missed all 5 vulnerable samples. Do not use them to claim model performance.
- LLM+SAST had Semgrep parsing errors on 3 of the 10 pilot functions. Failed scans are retained and are not treated as clean.
- NVD overlap with benchmark CVE descriptions cannot be fully ruled out even with the CVE exclusion filter.
- The bundled Semgrep YAML is a tiny research ruleset, not a production pack.
- Hash embedder is for tests only.

## Next steps after the 10-sample pilot

1. Review `paper_results/README.md` and decide whether the 10-sample failure pattern justifies continuing.
2. If continuing, inspect and address Semgrep parse failures and validate the LLM prompt / model scores before increasing the sample count.
3. Run the next small chunk on the PrimeVul test split; keep the split and threshold fixed and record the chosen sample IDs.
4. Fill `research/observations_template.md` without claiming superiority from pilot results.
