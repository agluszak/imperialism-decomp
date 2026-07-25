"""Isolated Wine-prefix lifecycle shared by semantic tests and smoke tools."""

from __future__ import annotations

import os
from pathlib import Path
import fcntl
import hashlib
import json
import shutil
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build-runtime-tests"
PREFIX_TEMPLATE_SCHEMA = 2
SEEDED_REGISTRY_VALUES = (
    ("AutoRes", "REG_DWORD", "0"),
    ("Language", None, "ENGLISH"),
)

# Wine's own virtual desktop. On a bare Xvfb there is no window manager, so nothing
# activates the game window and its paint path never primes the render cache -- several
# scenarios assert on that cache. Explorer's desktop supplies activation itself, which
# makes off-screen runs behave like a managed desktop.
VIRTUAL_DESKTOP_GEOMETRY = "1024x768"


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


def populate_wine_prefix(prefix: Path, virtual_desktop: bool = False) -> None:
    prefix.mkdir(parents=True, exist_ok=True)
    environment = prefix_environment(prefix)
    subprocess.run(["wineboot", "--init"], env=environment, check=True, capture_output=True, timeout=180)
    settings_key = "HKCU\\Software\\SSI\\Imperialism\\Settings"
    for name, value_type, value in SEEDED_REGISTRY_VALUES:
        value_args = ["/v", name]
        if value_type is not None:
            value_args.extend(["/t", value_type])
        value_args.extend(["/d", value])
        subprocess.run(
            ["wine", "reg", "add", settings_key, *value_args, "/f"],
            env=environment,
            check=True,
            capture_output=True,
            timeout=60,
        )
    if virtual_desktop:
        _seed_virtual_desktop(environment)
    subprocess.run(["wineserver", "--wait"], env=environment, check=False, capture_output=True, timeout=180)


def _seed_virtual_desktop(environment: dict[str, str]) -> None:
    for key, name, value in (
        ("HKCU\\Software\\Wine\\Explorer", "Desktop", "Default"),
        ("HKCU\\Software\\Wine\\Explorer\\Desktops", "Default", VIRTUAL_DESKTOP_GEOMETRY),
    ):
        subprocess.run(
            ["wine", "reg", "add", key, "/v", name, "/d", value, "/f"],
            env=environment,
            check=False,
            capture_output=True,
            timeout=60,
        )


def template_identity(wine_version: str, virtual_desktop: bool = False) -> str:
    payload = {
        "schema": PREFIX_TEMPLATE_SCHEMA,
        "seeded_registry_values": SEEDED_REGISTRY_VALUES,
        "virtual_desktop": VIRTUAL_DESKTOP_GEOMETRY if virtual_desktop else None,
        "wine_version": wine_version,
    }
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode()).hexdigest()[:16]


def ensure_template_prefix(virtual_desktop: bool = False) -> Path:
    wine_version = subprocess.run(
        ["wine", "--version"], capture_output=True, text=True, check=True
    ).stdout.strip()
    identity = template_identity(wine_version, virtual_desktop)
    template = BUILD_DIR / f"wineprefix-template-{identity}"
    stamp = template / ".imperialism-template"
    expected_stamp = json.dumps(
        {"identity": identity, "schema": PREFIX_TEMPLATE_SCHEMA, "wine": wine_version},
        sort_keys=True,
    )
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    lock_path = BUILD_DIR / "wineprefix-template.lock"
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            if stamp.read_text(encoding="utf-8").strip() == expected_stamp:
                return template
        except OSError:
            pass
        staging = BUILD_DIR / f".{template.name}.build-{os.getpid()}"
        shutil.rmtree(staging, ignore_errors=True)
        populate_wine_prefix(staging, virtual_desktop)
        (staging / stamp.name).write_text(expected_stamp + "\n", encoding="utf-8")
        try:
            staging.rename(template)
        except FileExistsError:
            shutil.rmtree(staging, ignore_errors=True)
        if not stamp.is_file():
            raise RuntimeError(f"Wine-prefix template publication failed: {template}")
        return template


def initialize_wine_prefix(prefix: Path, environment: dict[str, str]) -> None:
    virtual_desktop = bool(environment.get("IMPERIALISM_WINE_VIRTUAL_DESKTOP"))
    subprocess.run(
        ["cp", "-a", "--reflink=auto", str(ensure_template_prefix(virtual_desktop)), str(prefix)],
        check=True,
        capture_output=True,
        timeout=180,
    )


def shut_down_wine_prefix(environment: dict[str, str]) -> None:
    subprocess.run(["wineserver", "-k"], env=environment, check=False, capture_output=True)
    subprocess.run(
        ["wineserver", "--wait"], env=environment, check=False, capture_output=True, timeout=60
    )
