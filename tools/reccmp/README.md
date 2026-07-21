# reccmp Workflow

`reccmp` is installed from the pinned fork in `pyproject.toml` and executed with `uv run`.

Primary workflow uses `just` wrappers:

1. `just detect`
2. `just compare 0xADDR` (or `just compare`)
3. `just stats` (compare against the committed progress baseline)
4. `just stats-baseline-update` (update the committed progress baseline after accepting changes)
5. `just session-loop` (read-only ranking; pass `--refresh-ignore` to also rewrite ignore lists)

`just compare 0xA 0xB` and `just triage 0xA 0xB` pass those addresses into
reccmp before comparison. They parse the PDB once and do not build a full-corpus
report. Targeted runs load only conservatively resolved PDB object modules and reuse
validated parsed-analysis state in `build-msvc500/.reccmp-cache`; comparison and proof
results are always recomputed. `just addr` uses the same targeted path in both address
spaces.

`just stats-baseline-update` writes two reviewable snapshots:

- `config/baselines/reccmp_progress_baseline.json` — aggregate counts and ratios.
- `config/baselines/reccmp_progress_baseline.functions.csv` — only the per-function
  address, effective score, and name needed by regression checks and candidate tools.

The full structured `build-msvc500/reccmp_report.json` is disposable live evidence
for triage; it is not committed as a baseline. Full progress reports are reused only
when `reccmp_report.inputs.json` proves identical hashes for both binaries, the PDB,
reccmp configuration and version lock, generated data sources, and every configured
source-root file, and also proves that the roadmap/report outputs are untampered.
This lets the immediately following `stats-baseline-update` reuse accepted live
evidence without making stale reports authoritative.

Progress reports deliberately include functions listed under
`report.ignore_functions`. That setting only suppresses library/framework noise in
interactive reccmp output; changing a presentation filter must not change
exact-function counts or average similarity. Progress metrics also exclude vtables and
stubs.

Bootstrap project metadata once:

```bash
uv run reccmp-project create --originals /absolute/path/to/Imperialism.exe --scm
```

Direct CLI (if needed):

```bash
uv run reccmp-project --help
uv run reccmp-reccmp --help
uv run reccmp-ghidra-import --help
```
