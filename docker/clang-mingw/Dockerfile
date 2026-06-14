# Modern second compiler for early error catching (NOT used for reccmp).
#
# clang targeting i686-w64-mingw32: MinGW-w64 supplies <windows.h>, gdi32/user32
# and all MSVC calling conventions (__fastcall/__thiscall/__stdcall/__cdecl),
# while clang at C++14 turns on the real `override`/`static_assert` that MSVC 5.0
# silently ignores. See docker/msvc500 for the reccmp-matching build.
FROM debian:stable-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    ca-certificates \
    clang \
    lld \
    mingw-w64 \
    cmake \
    ninja-build \
    python3 \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.py /entrypoint.py

ENTRYPOINT ["python3", "/entrypoint.py"]
