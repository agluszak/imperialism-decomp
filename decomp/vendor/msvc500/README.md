# MSVC 5.0 Header Mirror

`headers/` is a local, gitignored mirror of the MSVC 5.0 headers used by the
Docker build image:

- `include/`
- `mfc/include/`
- `atl/include/`

Populate or refresh it with:

```bash
just vendor-msvc500-headers
```

By default the helper clones the same portable toolchain source used by
`docker/msvc500/Dockerfile` (`archaic-msvc/msvc500`) and copies only the header
directories. To copy from an existing local MSVC tree instead:

```bash
just vendor-msvc500-headers --source /path/to/msvc
```

The mirror is for local source-reference and signature-recovery work only; do
not include these proprietary/runtime headers in git.
