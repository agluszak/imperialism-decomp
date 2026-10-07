# MSVC 5.0 build image

Build the pinned VC5/Clang 21 image from `decomp/` with
`just docker-build` (or directly with
`docker build -t imperialism-msvc500 -f docker/msvc500/Dockerfile docker/msvc500`).

The image compiles the historical game with MSVC 5.0 under Wine and
provides the LLVM 21 source-index and clang-tidy tooling.
Use `just build`, `just source-index`, and `just lint` rather than
maintaining separate container invocations.

The [scalar analysis plugin](clang-tidy-plugin/README.md) is compiled
into the image. Rebuild the image after changing its Dockerfile or plugin.
