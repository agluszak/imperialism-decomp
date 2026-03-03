# reccmp Workflow

`reccmp` is installed from the pinned fork in `pyproject.toml` and executed with `uv run`.

Primary workflow uses `just` wrappers:

1. `just detect`
2. `just compare 0xADDR` (or `just compare`)
3. `just stats`
4. `just compare-canaries`
5. `just session-loop`

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
