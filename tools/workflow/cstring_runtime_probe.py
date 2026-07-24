#!/usr/bin/env python3
"""Compile and run a public-API CString lifetime probe with VC5/MFC 4.2.

The probe deliberately treats CString as opaque.  It checks the source-visible ABI
and lifetime behavior needed by the reconstruction without reading m_pchData or
CStringData internals.
"""

from __future__ import annotations

import argparse
import subprocess
import tempfile
from pathlib import Path

from tools.common.repo import repo_root_from_file


DOCKER_IMAGE = "imperialism-msvc500:latest"
SUCCESS_LINE = "CString VC5 runtime probe passed"

PROBE_SOURCE = r'''#include <afx.h>
#include <stdio.h>
#include <string.h>

static int g_failures = 0;

static void Check(int condition, const char* message) {
    if (!condition) {
        ++g_failures;
        printf("FAIL: %s\n", message);
    }
}

struct EmbeddedStrings {
    CString values[3];
};

struct UnwindSentinel {
    static int destroyed;
    CString text;

    ~UnwindSentinel() {
        ++destroyed;
    }
};

int UnwindSentinel::destroyed = 0;

static CString MakeValue(void) {
    CString prefix("return");
    CString suffix("-value");
    return prefix + suffix;
}

static void ThrowWithCString(void) {
    UnwindSentinel sentinel;
    sentinel.text = "unwind";
    throw 7;
}

int main(void) {
    Check(sizeof(CString) == 4, "CString object is not four bytes");

    CString empty;
    Check(empty.IsEmpty(), "default CString is not empty");
    Check(empty.GetLength() == 0, "default CString length is not zero");

    CString original("alpha");
    CString copy(original);
    copy.SetAt(0, 'A');
    Check(original == "alpha", "copy-on-write changed the source");
    Check(copy == "Alpha", "copy-on-write mutation failed");

    CString shared("xxxxx");
    CString bufferCopy(shared);
    char* buffer = bufferCopy.GetBufferSetLength(5);
    memcpy(buffer, "hello", 5);
    bufferCopy.ReleaseBuffer(5);
    Check(shared == "xxxxx", "GetBuffer mutation changed a shared source");
    Check(bufferCopy == "hello", "GetBuffer/ReleaseBuffer mutation failed");

    {
        EmbeddedStrings embedded;
        embedded.values[0] = "zero";
        embedded.values[1] = embedded.values[0];
        embedded.values[2] = "two";
        embedded.values[1].SetAt(0, 'Z');
        Check(embedded.values[0] == "zero", "embedded array COW failed");
        Check(embedded.values[1] == "Zero", "embedded array mutation failed");
        Check(embedded.values[2] == "two", "embedded array construction failed");
    }

    CString returned = MakeValue();
    Check(returned == "return-value", "CString return-by-value failed");

    try {
        ThrowWithCString();
    } catch (int value) {
        Check(value == 7, "unexpected exception value");
    }
    Check(UnwindSentinel::destroyed == 1,
          "CString-containing local was not destroyed during unwind");

    if (g_failures != 0) {
        printf("CString VC5 runtime probe failed: %d checks\n", g_failures);
        return 1;
    }
    printf("CString VC5 runtime probe passed\n");
    return 0;
}
'''


def compile_and_run(work_dir: Path, repo_root: Path) -> str:
    work_dir.mkdir(parents=True, exist_ok=True)
    (work_dir / "cstring_probe.cpp").write_text(PROBE_SOURCE, encoding="ascii")

    script = (
        "wine C:/msvc/bin/CL.EXE /nologo /GX /GR- /MT /W3 "
        "cstring_probe.cpp nafxcw.lib advapi32.lib shell32.lib comctl32.lib "
        "comdlg32.lib winspool.lib ole32.lib oleaut32.lib oledlg.lib uuid.lib "
        "/link /subsystem:console /out:cstring_probe.exe > cl.log 2>&1; "
        "status=$?; tail -40 cl.log >&2; "
        "if [ $status -ne 0 ] || [ ! -f cstring_probe.exe ]; then "
        "echo CSTRING_PROBE_COMPILE_FAILED >&2; exit 1; fi; "
        "wine ./cstring_probe.exe 2>/dev/null"
    )
    cmd = [
        "docker", "run", "--rm", "--network", "none",
        "--entrypoint", "/bin/sh",
        "-e", r"INCLUDE=C:\dxsdk\include;C:\msvc\include;C:\msvc\mfc\include;C:\msvc\atl\include",
        "-e", r"LIB=C:\msvc\lib;C:\msvc\mfc\lib",
        "-e", r"WINEPATH=C:\msvc\bin;C:\msvc\redist",
        "-v", f"{repo_root}:/imperialism:ro",
        "-v", f"{work_dir}:/work", "-w", "/work",
        DOCKER_IMAGE, "-c", script,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"CString runtime probe failed (rc={proc.returncode}):\n"
            f"{proc.stderr[-5000:]}\n{proc.stdout[-2000:]}")
    if SUCCESS_LINE not in proc.stdout:
        raise RuntimeError(
            "CString runtime probe did not emit its success marker:\n"
            f"{proc.stderr[-3000:]}\n{proc.stdout[-2000:]}")
    return proc.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--work-dir",
        help="Keep generated source, compiler log, and executable in this directory.",
    )
    args = parser.parse_args()
    repo_root = repo_root_from_file(__file__)
    if args.work_dir:
        output = compile_and_run(Path(args.work_dir).resolve(), repo_root)
    else:
        with tempfile.TemporaryDirectory(prefix="cstring_runtime_probe_") as tmp:
            output = compile_and_run(Path(tmp), repo_root)
    print(output.strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
