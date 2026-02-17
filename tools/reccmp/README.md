# reccmp Bootstrap

Install `reccmp` into a local virtual environment and optionally create project config files.

## Usage

```bash
uv run python tools/reccmp/bootstrap_reccmp.py
```

With original binary path (recommended for first setup):

```bash
uv run python tools/reccmp/bootstrap_reccmp.py \
  --original-binary /absolute/path/to/Imperialism.exe
```

Optional variables:

- `--original-binary` (optional; enables `reccmp-project create`)

After bootstrap:

```bash
uv run --group reccmp reccmp-project --help
uv run --group reccmp reccmp-reccmp --help
```
