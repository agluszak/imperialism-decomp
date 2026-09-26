# MSVC 5.0 Docker Build

This image provides a reproducible Linux-hosted build path for old MSVC via Wine.

## Build Image

```bash
docker build -t imperialism-msvc500 -f docker/msvc500/Dockerfile docker/msvc500
```

Rebuild this image after updating its Dockerfile. The native reccmp source collector requires the
LLVM 19 development libraries installed by the image; older images cannot run `just source-index`.

`just build` collects Clang source facts after building the VC5 executable and recording its PDB.
The collector reads the production sources and generated factories through the existing Clang CMake
profile, without compiling a replacement executable. Its cached output lives under
`build-msvc500/reccmp-source/`, and `reccmp-build.yml` points comparison tools at that source index.

## Configure + Build

```bash
mkdir -p build-msvc500
docker run --rm \
  -e CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=RelWithDebInfo" \
  -v "$PWD":/imperialism \
  -v "$PWD/build-msvc500":/build \
  imperialism-msvc500
```

Defaults:

- Generator: `NMake Makefiles`
- Source: `/imperialism` (mounted to `Z:\imperialism` in Wine)
- Build: `/build` (mounted to `Z:\build` in Wine)

Optional environment variable:

- `CMAKE_GENERATOR` (for advanced experiments)
