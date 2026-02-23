# MSVC 4.20 Docker Build

This image provides a reproducible Linux-hosted build path for old MSVC via Wine.

## Build Image

```bash
docker build -t imperialism-msvc420 -f docker/msvc420/Dockerfile docker/msvc420
```

## Configure + Build

```bash
mkdir -p build-msvc420
docker run --rm \
  -e CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=RelWithDebInfo" \
  -v "$PWD":/imperialism \
  -v "$PWD/build-msvc420":/build \
  imperialism-msvc420
```

Defaults:

- Generator: `NMake Makefiles`
- Source: `/imperialism` (mounted to `Z:\imperialism` in Wine)
- Build: `/build` (mounted to `Z:\build` in Wine)

Optional environment variable:

- `CMAKE_GENERATOR` (for advanced experiments)
