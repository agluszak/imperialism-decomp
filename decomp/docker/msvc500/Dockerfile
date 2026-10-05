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

# The pinned reccmp collector uses the LLVM 21 AST and CodeGen APIs.
RUN echo "deb http://deb.debian.org/debian trixie-backports main" \
      > /etc/apt/sources.list.d/backports.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends -t trixie-backports \
      clang-21 clang-tidy-21 llvm-21-dev libclang-21-dev libclang-cpp21-dev \
 && rm -rf /var/lib/apt/lists/* \
 && ln -sf clang-21 /usr/bin/clang-cl

# Whole-program scalar facts: the LLVM 21 clang-tidy plugin, its solver and self-tests.
# The wrapper replaces clang-tidy and loads the plugin into clang-tidy-21.
COPY clang-tidy-plugin /tmp/imperialism-clang-tidy-plugin
RUN cmake \
      -S /tmp/imperialism-clang-tidy-plugin \
      -B /tmp/imperialism-clang-tidy-plugin/build \
      -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DLLVM_DIR=/usr/lib/llvm-21/lib/cmake/llvm \
      -DClang_DIR=/usr/lib/llvm-21/lib/cmake/clang \
 && cmake --build /tmp/imperialism-clang-tidy-plugin/build \
 && cmake --install /tmp/imperialism-clang-tidy-plugin/build \
 && install -m 0755 /tmp/imperialism-clang-tidy-plugin/clang-tidy-wrapper.py /usr/local/bin/clang-tidy \
 && install -m 0644 /tmp/imperialism-clang-tidy-plugin/scalar_facts.py /usr/local/bin/scalar_facts.py \
 && test "$(command -v clang-tidy)" = /usr/local/bin/clang-tidy \
 && cd /tmp/imperialism-clang-tidy-plugin \
 && clang-tidy --imperialism-wrapper-self-test \
 && for check in redundant-scalar-cast bool-like-byte scalar-facts; do \
      clang-tidy --checks=-*,imperialism-$check --list-checks | grep -q "imperialism-$check" || exit 1; \
    done \
 && IMPERIALISM_REDUNDANT_CAST_LINES='*' clang-tidy \
      --checks=-*,imperialism-redundant-scalar-cast test.cpp \
      -- --target=i686-pc-windows-msvc -std=c++17 > test.log 2>&1 \
 && test "$(grep -c '\[imperialism-redundant-scalar-cast\]' test.log)" -eq 7 \
 && IMPERIALISM_REDUNDANT_CAST_LINES='/home/build/imperialism/include/game/clang_tidy_record_fixture_types.h@1-200;/home/build/imperialism/include/game/clang_tidy_record_fixture_macros.h@1-20;/home/build/imperialism/src/game/clang_tidy_record_cast_fixture.cpp@1-500;/home/build/imperialism/src/game/clang_tidy_record_cast_fixture_second.cpp@1-50' \
      clang-tidy --checks=-*,imperialism-project-record-reinterpret-cast --header-filter=.* \
      record_cast_fixture.cpp record_cast_fixture_second.cpp \
      -- --target=i686-pc-windows-msvc -std=c++17 > record_cast_fixture.log 2>&1 \
 && test "$(grep -c '\[imperialism-project-record-reinterpret-cast\]' record_cast_fixture.log)" -eq 18 \
 && grep -q "repository record 'cast_fixture::A' to repository record 'cast_fixture::B'" record_cast_fixture.log \
 && grep -q "source record 'cast_fixture::A\*' is erased here" record_cast_fixture.log \
 && grep -q "repository record 'cast_fixture::Renderer::Pick'" record_cast_fixture.log \
 && grep -q 'source record provenance .* is unresolved' record_cast_fixture.log \
 && IMPERIALISM_REDUNDANT_CAST_LINES='*' clang-tidy \
      --checks=-*,imperialism-project-record-reinterpret-cast --header-filter=.* \
      record_cast_fixture.cpp record_cast_fixture_second.cpp record_cast_fixture_empty.cpp \
      -- --target=i686-pc-windows-msvc -std=c++17 -I . > record_cast_audit.log 2>&1 \
 && test "$(grep -c '\[imperialism-project-record-reinterpret-cast\]' record_cast_audit.log)" -eq 18 \
 && IMPERIALISM_REDUNDANT_CAST_LINES="$PWD/bool_test.cpp@1-300" clang-tidy \
      --checks=-*,imperialism-bool-like-byte --warnings-as-errors=* bool_test.cpp \
      -- --target=i686-pc-windows-msvc -std=c++17 > bool_test.log 2>&1 \
 && test "$(grep -c 'warning:.*\[imperialism-bool-like-byte\]' bool_test.log)" -eq 17 \
 && grep -q 'explicit full-tree audit mode selected' record_cast_audit.log \
 && for candidate in HasEntries Both HasLineOfSightToBounds0046FD70 m_dirty \
      selection_settled settled transition_active left_ready right_ready both_ready \
      fCombatMode talking execution_active_000 initialized display_active \
      SetPanelVisible::visible handed_ready; do \
      grep -q "'$candidate'" bool_test.log || exit 1; \
    done \
 && ! grep -Eq 'error:|use bool|bool-byte-ok' bool_test.log \
 && ! grep -Eq 'SetPanelLayered|SetCallbackEnabled|g_menu_active|has_group|monster_bound|nested_active' \
      bool_test.log \
 && if IMPERIALISM_REDUNDANT_CAST_LINES="$PWD/bool_test.cpp@1-300" clang-tidy \
      --checks=-*,imperialism-bool-like-byte bool_test.cpp \
      -- --target=i686-pc-windows-msvc -std=c++17 -DIMPERIALISM_BOOL_TEST_INVALID \
      > bool_test_invalid.log 2>&1; then cat bool_test_invalid.log; exit 1; fi \
 && grep -q '\[clang-diagnostic-error\]' bool_test_invalid.log \
 && IMPERIALISM_SCALAR_FACTS_DIR="$PWD/scalar-facts" clang-tidy \
      --checks=-*,imperialism-bool-like-byte,imperialism-scalar-facts \
      scalar_test.cpp scalar_test_second.cpp \
      -- --target=i686-pc-windows-msvc -std=c++17 -isystem scalar_system \
 && python3 scalar_test.py scalar-facts \
 && cd / \
 && rm -rf /tmp/imperialism-clang-tidy-plugin

COPY entrypoint.py /entrypoint.py

ENTRYPOINT ["python3", "/entrypoint.py"]
