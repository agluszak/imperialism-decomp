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

# Registry seeded only for off-screen (Xvfb) runs. There is no window manager there, so
# Wine's managed-window path has nobody to hand mapping and placement to; Managed=N makes
# Wine own its windows outright instead of waiting on a WM that will never answer.
VIRTUAL_DISPLAY_REGISTRY = (
    ("HKCU\\Software\\Wine\\X11 Driver", "Managed", "N"),
)


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
    for key, name, value in VIRTUAL_DISPLAY_REGISTRY:
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
        "virtual_desktop": VIRTUAL_DISPLAY_REGISTRY if virtual_desktop else None,
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


# State a run mutates and the next run must not inherit. Everything else in the prefix
# (notably the ~1.2 GB drive_c/windows builtin DLL tree) is effectively read-only, which
# is what makes reusing one prefix per worktree safe.
MUTABLE_PREFIX_TREES = (Path("drive_c/users"),)


def worktree_prefix() -> Path:
    """The single Wine prefix this worktree reuses across runs.

    BUILD_DIR is repo-local and gitignored, so this is per worktree by construction:
    concurrent agents each get their own prefix and their own wineserver, and none of
    them can kill another's game with `wineserver -k`.
    """
    return BUILD_DIR / "wineprefix"


def _clone_tree(source: Path, destination: Path) -> None:
    subprocess.run(
        ["cp", "-a", "--reflink=auto", str(source), str(destination)],
        check=True,
        capture_output=True,
        timeout=180,
    )


def _restore_mutable_state(prefix: Path, template: Path) -> None:
    """Reset the parts of the prefix a previous run may have changed.

    Only the user profile is restored. The registry hives are deliberately left alone:
    a warm wineserver holds them in memory, so rewriting the files under it would not
    reset anything and would risk the server flushing its cached copy back over the
    restored one. Registry drift across runs is therefore an accepted cost of the warm
    server -- see the trade recorded on imperialism-decomp-3sn1.
    """
    for relative in MUTABLE_PREFIX_TREES:
        source = template / relative
        if not source.is_dir():
            continue
        target = prefix / relative
        shutil.rmtree(target, ignore_errors=True)
        target.parent.mkdir(parents=True, exist_ok=True)
        _clone_tree(source, target)


def initialize_wine_prefix(prefix: Path, environment: dict[str, str]) -> None:
    """Make `prefix` ready for a run, materializing it from the template on first use.

    Runs used to get a private prefix copied per test. That cost a full 1.3 GB byte copy
    on any filesystem without reflink support (build-runtime-tests is on ext4 here), plus
    an rmtree of the same size on teardown, for isolation that a per-worktree prefix
    already provides -- each agent works in its own worktree, so nobody shares a
    wineserver with anybody else. See imperialism-decomp-3sn1.
    """
    virtual_desktop = bool(environment.get("IMPERIALISM_WINE_VIRTUAL_DESKTOP"))
    template = ensure_template_prefix(virtual_desktop)
    if not (prefix / "system.reg").is_file():
        shutil.rmtree(prefix, ignore_errors=True)
        prefix.parent.mkdir(parents=True, exist_ok=True)
        _clone_tree(template, prefix)
        return
    _restore_mutable_state(prefix, template)


def shut_down_wine_prefix(environment: dict[str, str]) -> None:
    subprocess.run(["wineserver", "-k"], env=environment, check=False, capture_output=True)
    subprocess.run(
        ["wineserver", "--wait"], env=environment, check=False, capture_output=True, timeout=60
    )
