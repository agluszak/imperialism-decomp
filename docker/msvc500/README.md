# MSVC 5.0 Docker Build

This image provides a reproducible Linux-hosted build path for old MSVC via Wine.

## Build Image

```bash
docker build -t imperialism-msvc500 -f docker/msvc500/Dockerfile docker/msvc500
```

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
