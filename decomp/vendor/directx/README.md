# DirectX 5 SDK Mirror

`include/` and `lib/` are a local, gitignored mirror of the DirectX 5 SDK
(August 1997) headers and import libraries baked into the Docker build image
at `C:\dxsdk` (see `docker/msvc500/Dockerfile`).

The game targets **IDirectPlay2**; the portable MSVC 5.0 toolchain only ships
the DirectX 1 `<dplay.h>`, so `C:\dxsdk\include` is placed ahead of
`C:\msvc\include` on the `INCLUDE` path to shadow it.

Populate or refresh the mirror with:

```bash
just vendor-directx-headers
```

By default the helper downloads the same archive.org installer used by the
Docker image (`idx5sdk.exe`) and extracts `sdk/inc` + `sdk/lib`. To copy from
an already-extracted SDK tree or a local installer instead:

```bash
just vendor-directx-headers --source /path/to/sdk-or-idx5sdk.exe
```

The mirror is for local source-reference and signature-recovery work only; do
not include these proprietary headers/libs in git.
