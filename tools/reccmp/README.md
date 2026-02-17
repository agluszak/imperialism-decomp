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
