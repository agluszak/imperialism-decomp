# reccmp Bootstrap

`reccmp` currently pins `pyghidra==2.2.0`, while this project venv uses `pyghidra==3.0.2`.
To avoid version conflicts, `reccmp` is installed in a dedicated environment:

- `.venv-reccmp`

## Bootstrap

```bash
uv run python tools/reccmp/bootstrap_reccmp.py
```

With original binary path (recommended for first setup):

```bash
uv run python tools/reccmp/bootstrap_reccmp.py \
  --original-binary /absolute/path/to/Imperialism.exe
```

## Run reccmp tools

```bash
uv run python tools/reccmp/run_reccmp_tool.py reccmp-project --help
uv run python tools/reccmp/run_reccmp_tool.py reccmp-reccmp --help
```

Typical flow after building:

```bash
uv run python tools/reccmp/run_reccmp_tool.py --cwd build-msvc500 reccmp-project detect --what recompiled
uv run python tools/reccmp/run_reccmp_tool.py --cwd build-msvc500 reccmp-reccmp --target IMPERIALISM
```
