"""Isolated Wine-prefix lifecycle shared by semantic tests and smoke tools."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build-runtime-tests"


def retail_game_dir() -> Path:
    original = os.environ.get("ORIGINAL_BINARY")
    if not original:
        raise SystemExit("Set ORIGINAL_BINARY in .env")
    return Path(original).resolve().parent


def windows_path(path: Path, environment: dict[str, str]) -> str:
    completed = subprocess.run(
        ["winepath", "-w", str(path.resolve())],
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return completed.stdout.strip()


def prefix_environment(prefix: Path) -> dict[str, str]:
    environment = dict(os.environ)
    environment["WINEPREFIX"] = str(prefix)
    environment["WINEDEBUG"] = environment.get("WINEDEBUG", "-all")
    environment.setdefault("WINEDLLOVERRIDES", "mscoree,mshtml=")
    return environment


def populate_wine_prefix(prefix: Path) -> None:
    prefix.mkdir(parents=True, exist_ok=True)
    environment = prefix_environment(prefix)
    subprocess.run(["wineboot", "--init"], env=environment, check=True, capture_output=True, timeout=180)
    settings_key = "HKCU\\Software\\SSI\\Imperialism\\Settings"
    for value_args in (
        ["/v", "AutoRes", "/t", "REG_DWORD", "/d", "0"],
        ["/v", "Language", "/d", "ENGLISH"],
    ):
        subprocess.run(
            ["wine", "reg", "add", settings_key, *value_args, "/f"],
            env=environment,
            check=True,
            capture_output=True,
            timeout=60,
        )
    subprocess.run(["wineserver", "--wait"], env=environment, check=False, capture_output=True, timeout=180)


def ensure_template_prefix() -> Path:
    template = BUILD_DIR / "wineprefix-template"
    stamp = template / ".imperialism-template"
    wine_version = subprocess.run(
        ["wine", "--version"], capture_output=True, text=True, check=True
    ).stdout.strip()
    try:
        if stamp.read_text(encoding="utf-8").strip() == wine_version:
            return template
    except OSError:
        pass
    staging = template.with_name(f"{template.name}.build-{os.getpid()}")
    shutil.rmtree(staging, ignore_errors=True)
    populate_wine_prefix(staging)
    (staging / stamp.name).write_text(wine_version + "\n", encoding="utf-8")
    shutil.rmtree(template, ignore_errors=True)
    try:
        staging.rename(template)
    except OSError:
        shutil.rmtree(staging, ignore_errors=True)
    return template


def initialize_wine_prefix(prefix: Path, environment: dict[str, str]) -> None:
    del environment
    subprocess.run(
        ["cp", "-a", "--reflink=auto", str(ensure_template_prefix()), str(prefix)],
        check=True,
        capture_output=True,
        timeout=180,
    )


def shut_down_wine_prefix(environment: dict[str, str]) -> None:
    subprocess.run(["wineserver", "-k"], env=environment, check=False, capture_output=True)
    subprocess.run(
        ["wineserver", "--wait"], env=environment, check=False, capture_output=True, timeout=60
    )
