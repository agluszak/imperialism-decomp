# reccmp Usage

`reccmp` is installed in the project environment from your fork via `pyproject.toml`.
Use it directly with `uv run`.

## Bootstrap project files

```bash
uv run reccmp-project create \
  --originals /absolute/path/to/Imperialism.exe \
  --scm
```

## Run reccmp tools

```bash
uv run reccmp-project --help
uv run reccmp-reccmp --help
uv run reccmp-ghidra-import --help
```

Typical flow after building:

```bash
(cd build-msvc500 && uv run reccmp-project detect --what recompiled)
(cd build-msvc500 && uv run reccmp-reccmp --target IMPERIALISM)
```

## Progress stats script

Use this to get one-line-direction deltas (better/worse/stalled) between runs:

```bash
uv run python tools/reccmp/progress_stats.py --target IMPERIALISM
```

If you already have `reccmp_roadmap.csv` and `reccmp_report.json` generated and only want to recompute/print:

```bash
uv run python tools/reccmp/progress_stats.py --target IMPERIALISM --no-run
```

## Core impact ranking

Rank core work by `size * (1 - similarity)` while excluding known non-core buckets
(CRT/MFC/DirectX/wrappers/thunks by default):

```bash
uv run python tools/reccmp/core_impact_ranking.py \
  --target IMPERIALISM \
  --top 50 \
  --csv-out build-msvc500/core_impact.csv \
  --json-out build-msvc500/core_impact.json
```

This also prints wrapper relabel candidates to keep library adapters out of core metrics.

## Session loop (one command)

Generate the working queue for the next coding session:

```bash
uv run python tools/reccmp/session_loop.py \
  --target IMPERIALISM \
  --pick 8 \
  --top 50 \
  --min-size 1
```

Outputs:

- `build-msvc500/next_loop.md`
- `build-msvc500/next_loop.json`
- refreshed `build-msvc500/core_impact.{json,csv}`

## Flag Sweep

Sweep candidate MSVC optimization profiles and score them with `reccmp`:

```bash
uv run python tools/reccmp/flag_sweep.py \
  --target IMPERIALISM \
  --docker-image imperialism-msvc500 \
  --build-root build-flag-sweep \
  --address 0x00606fc0 \
  --address 0x00606fd2 \
  --json-out build-flag-sweep/results.json
```

The sweep uses CMake cache variables:

- `IMPERIALISM_MATCH_FLAGS_CSV`
- `IMPERIALISM_MATCH_LINK_FLAGS_CSV`

Both accept comma-separated flag lists, for example `/O2,/Ob2,/Oy`.

Current recommendation from the latest sweep:

- Keep baseline `RelWithDebInfo` defaults (`/O2 /Ob1` from CMake's MSVC profile).
- Do not force `/O1` or `/Ob2` globally; they reduced average similarity and/or aligned count.
- Use per-function experiments with `IMPERIALISM_MATCH_FLAGS_CSV` only when a specific function improves.
