FROM debian:stable-slim

RUN dpkg --add-architecture i386 \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    p7zip-full \
    python3 \
    unzip \
    wget \
    wine \
    wine32 \
    clang \
    clang-tidy \
    lld \
    llvm \
    cmake \
    ninja-build \
 && rm -rf /var/lib/apt/lists/*

RUN ln -sf clang /usr/bin/clang-cl \
 && ln -sf llvm-ar /usr/bin/llvm-lib \
 && ln -sf lld-link /usr/bin/lld-link

# Initialize wine prefix once at build time.
RUN wine wineboot --init || true

# Portable VC++ 5 toolchain.
RUN git clone --depth 1 https://github.com/archaic-msvc/msvc500.git \
    /root/.wine/drive_c/msvc

# DirectX 5 SDK (Aug 1997) headers + import libs. The msvc500 toolchain only ships the
# DirectX 1 <dplay.h>; the game targets IDirectPlay2, so C:\dxsdk\include must shadow
# C:\msvc\include (see entrypoint.py INCLUDE order). The installer is a WEXTRACT SFX
# wrapping an MSZip cab; 7z unpacks both layers.
RUN wget -O /tmp/idx5sdk.exe https://archive.org/download/idx5sdk/idx5sdk.exe \
 && 7z x -o/tmp/dx5sfx -y /tmp/idx5sdk.exe DX5SDK.EXE \
 && 7z x -o/tmp/dx5 -y /tmp/dx5sfx/DX5SDK.EXE \
 && mkdir -p /root/.wine/drive_c/dxsdk \
 && cp -r /tmp/dx5/cdrom/sdk/inc /root/.wine/drive_c/dxsdk/include \
 && cp -r /tmp/dx5/cdrom/sdk/lib /root/.wine/drive_c/dxsdk/lib \
 && rm -rf /tmp/idx5sdk.exe /tmp/dx5sfx /tmp/dx5

# JOM: Qt's parallel drop-in nmake clone, for the "NMake Makefiles JOM" generator.
# VC5 predates /MP, so parallelism comes from the make layer. 1.1.3 is the last
# 32-bit jom (1.1.4+ is x64, which the win32 wine prefix cannot run).
RUN wget -O /tmp/jom.zip https://download.qt.io/official_releases/jom/jom_1_1_3.zip \
 && mkdir -p /root/.wine/drive_c/jom \
 && unzip /tmp/jom.zip -d /root/.wine/drive_c/jom \
 && rm -f /tmp/jom.zip

# Windows CMake for NMake generation.
RUN wget -O /tmp/cmake.zip https://github.com/Kitware/CMake/releases/download/v3.26.6/cmake-3.26.6-windows-i386.zip \
 && unzip /tmp/cmake.zip -d /root/.wine/drive_c/ \
 && mv /root/.wine/drive_c/cmake-3.26.6-windows-i386 /root/.wine/drive_c/cmake \
 && rm -f /tmp/cmake.zip

COPY entrypoint.py /entrypoint.py

ENTRYPOINT ["python3", "/entrypoint.py"]
