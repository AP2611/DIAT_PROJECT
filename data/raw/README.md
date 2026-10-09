# Raw knowledge files (immutable)

This directory is a **read-only view** of previously downloaded NVD, CWE, and CAPEC files.

On this machine the directories are symlinked to:

- `/Users/arjunpanse/Documents/security-knowledge-base/raw/nvd`
- `/Users/arjunpanse/Documents/security-knowledge-base/raw/cwe`
- `/Users/arjunpanse/Documents/security-knowledge-base/raw/capec`

Do not edit, overwrite, or delete those files. Normalization writes to `data/processed/` only.

Expected filenames:

- `nvd/nvdcve-2.0-YYYY.json`
- `cwe/cwec_v4.20.xml`
- `capec/capec_v3.9.xml`

Override the location with `VULNTRIAGE_RAW_DATA_DIR` or `paths.raw_data_dir` in `configs/default.yaml`.
