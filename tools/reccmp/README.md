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
