# LLM and LLM+SAST Readiness & Test Log

Date: 2026-10-29

## Runtime prerequisites
- Ollama daemon: running (v0.40.12), model `mistral:latest` available.
- Semgrep: installed v1.180.0, config `configs/semgrep.yml` present.
- Embeddings cache: present (all-MiniLM-L6-v2).
- Unit tests: 25 passed (`pytest -q`).

## Benchmark runs (synthetic smoke, n=3, --include-synthetic)
- llm_only run_id: 7914b93068e0
  - exports: results/exports/7914b93068e0.{jsonl,csv,metrics.json}
- llm_sast run_id: c5cf3547bd97
  - exports: results/exports/c5cf3547bd97.{jsonl,csv,metrics.json}

## Notes
- Synthetic smoke only; not suitable for paper claims. Import a labelled dataset (PrimeVul) for scientific metrics.
- Results are uncalibrated p_vulnerable scores; threshold 0.5.
