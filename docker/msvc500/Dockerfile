FROM debian:stable-slim

RUN dpkg --add-architecture i386 \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    python3 \
    unzip \
    wget \
    wine \
    wine32 \
 && rm -rf /var/lib/apt/lists/*

# Initialize wine prefix once at build time.
RUN wine wineboot --init || true

# Portable VC++ 5 toolchain.
RUN git clone --depth 1 https://github.com/archaic-msvc/msvc500.git \
    /root/.wine/drive_c/msvc

# Windows CMake for NMake generation.
RUN wget -O /tmp/cmake.zip https://github.com/Kitware/CMake/releases/download/v3.26.6/cmake-3.26.6-windows-i386.zip \
 && unzip /tmp/cmake.zip -d /root/.wine/drive_c/ \
 && mv /root/.wine/drive_c/cmake-3.26.6-windows-i386 /root/.wine/drive_c/cmake \
 && rm -f /tmp/cmake.zip

COPY entrypoint.py /entrypoint.py

ENTRYPOINT ["python3", "/entrypoint.py"]
