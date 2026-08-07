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
GAME_ASSET_STAMP_NAME = ".imperialism-assets.json"
GAME_ASSET_TEMPLATE_SCHEMA = 1
SETTINGS_KEY = "HKCU\\Software\\SSI\\Imperialism\\Settings"
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


def original_executable() -> Path:
    original = os.environ.get("ORIGINAL_BINARY")
    if not original:
        raise SystemExit("Set ORIGINAL_BINARY in .env")
    return Path(original).resolve()


def file_identity(path: Path) -> dict[str, object]:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "path": str(path),
        "size": path.stat().st_size,
        "sha256": digest.hexdigest(),
    }


def _drive_mappings(prefix: Path) -> list[tuple[Path, str]]:
    """Wine's drive letters as (host target, drive) pairs, longest target first.

    dosdevices/<letter>: is a symlink to the host directory the drive maps to, so the
    translation winepath performs is available by reading the prefix. Longest first so a
    nested mapping wins over the root drive.
    """
    mappings: list[tuple[Path, str]] = []
    for entry in sorted((prefix / "dosdevices").glob("?:")):
        try:
            target = entry.resolve(strict=True)
        except OSError:
            continue
        if target.is_dir():
            mappings.append((target, entry.name.upper()))
    mappings.sort(key=lambda item: len(str(item[0])), reverse=True)
    return mappings


def _translate_locally(path: Path, mappings: list[tuple[Path, str]]) -> str | None:
    resolved = path.resolve()
    for target, drive in mappings:
        if resolved == target:
            return f"{drive}\\"
        if target in resolved.parents:
            tail = str(resolved.relative_to(target)).replace("/", "\\")
            return f"{drive}\\{tail}"
    return None


def windows_paths(paths: list[Path], environment: dict[str, str]) -> list[str]:
    """Translate several host paths to Windows form in one winepath invocation.

    Each winepath call starts its own Wine process, which costs about a second even
    against a warm wineserver -- four separate calls were 4 s of every test's ~5.5 s.
    winepath accepts multiple operands and answers one line each, so the whole set costs
    what a single call did.
    """
    if not paths:
        return []
    prefix = Path(environment.get("WINEPREFIX", ""))
    if prefix.is_dir():
        # Pure-Python translation from the prefix's own drive map. Spawning winepath
        # costs about a second per invocation because it starts a Wine process, and it
        # was the single largest phase in a run once the server was kept warm.
        mappings = _drive_mappings(prefix)
        translated = [_translate_locally(path, mappings) for path in paths]
        if all(item is not None for item in translated):
            return [item for item in translated if item is not None]
    completed = subprocess.run(
        ["winepath", "-w", *[str(path.resolve()) for path in paths]],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    translated = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    if len(translated) != len(paths):
        raise RuntimeError(
            f"winepath returned {len(translated)} paths for {len(paths)} inputs"
        )
    return translated


def windows_path(path: Path, environment: dict[str, str]) -> str:
    return windows_paths([path], environment)[0]


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
    seed_runtime_registry(environment, virtual_desktop)
    subprocess.run(["wineserver", "--wait"], env=environment, check=False, capture_output=True, timeout=180)


def seed_runtime_registry(
    environment: dict[str, str], virtual_desktop: bool = False
) -> None:
    """Reset runtime-owned registry policy before every attempt.

    The prefix and wineserver stay warm, so replacing hive files on disk cannot reset
    live registry state. Deleting and recreating the game key through Wine is both
    deterministic and visible to the already-running server.
    """
    subprocess.run(
        ["wine", "reg", "delete", SETTINGS_KEY, "/f"],
        env=environment,
        check=False,
        capture_output=True,
        timeout=60,
    )
    for name, value_type, value in SEEDED_REGISTRY_VALUES:
        value_args = ["/v", name]
        if value_type is not None:
            value_args.extend(["/t", value_type])
        value_args.extend(["/d", value])
        subprocess.run(
            ["wine", "reg", "add", SETTINGS_KEY, *value_args, "/f"],
            env=environment,
            check=True,
            capture_output=True,
            timeout=60,
        )
    if virtual_desktop:
        _seed_virtual_desktop(environment)


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

    Only the user profile is restored from disk. A warm wineserver holds registry hives
    in memory, so `initialize_wine_prefix` resets runtime-owned keys through Wine after
    restoring the profile instead of replacing hive files behind the server's back.
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
    else:
        _restore_mutable_state(prefix, template)
    seed_runtime_registry(environment, virtual_desktop)


_GAME_ASSET_EXCLUDED_NAMES = {
    "imperialism.exe",
    "imperialism.exe.gog-original",
    "imperialism.exe.new",
    "imperialism.exe.pre-resource-run.bak",
    "imperialism.exe.recomp",
    "runtime-test-result.json",
}


def _is_game_asset(relative: Path) -> bool:
    if relative.parts and relative.parts[0].casefold() == "save":
        return False
    return relative.name.casefold() not in _GAME_ASSET_EXCLUDED_NAMES


def _game_asset_manifest(source: Path) -> tuple[str, list[dict[str, object]]]:
    rows = []
    for path in sorted(candidate for candidate in source.rglob("*") if candidate.is_file()):
        relative = path.relative_to(source)
        if not _is_game_asset(relative):
            continue
        identity = file_identity(path)
        rows.append(
            {
                "path": relative.as_posix(),
                "size": identity["size"],
                "sha256": identity["sha256"],
            }
        )
    payload = {
        "schema": GAME_ASSET_TEMPLATE_SCHEMA,
        "files": rows,
    }
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode()).hexdigest(), rows


def _make_tree_readonly(root: Path) -> None:
    for path in root.rglob("*"):
        path.chmod(0o555 if path.is_dir() else 0o444)
    root.chmod(0o555)


def _remove_tree(root: Path) -> None:
    """Remove a possibly read-only cache staging tree."""
    if not root.exists():
        return
    for path in root.rglob("*"):
        if path.is_dir():
            path.chmod(0o755)
    root.chmod(0o755)
    shutil.rmtree(root)


def ensure_game_asset_template() -> tuple[Path, str]:
    source = retail_game_dir()
    manifest_hash, rows = _game_asset_manifest(source)
    template = BUILD_DIR / f"game-assets-{manifest_hash[:16]}"
    stamp = template / GAME_ASSET_STAMP_NAME
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    with (BUILD_DIR / "game-assets.lock").open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            metadata = json.loads(stamp.read_text(encoding="utf-8"))
            if metadata.get("manifest_sha256") == manifest_hash:
                return template, manifest_hash
        except (OSError, ValueError):
            pass
        staging = BUILD_DIR / f".{template.name}.build-{os.getpid()}"
        _remove_tree(staging)
        staging.mkdir(parents=True)
        for row in rows:
            relative = Path(str(row["path"]))
            destination = staging / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                [
                    "cp",
                    "--reflink=auto",
                    "--preserve=mode,timestamps",
                    str(source / relative),
                    str(destination),
                ],
                check=True,
                capture_output=True,
                timeout=180,
            )
        (staging / stamp.name).write_text(
            json.dumps(
                {
                    "schema": GAME_ASSET_TEMPLATE_SCHEMA,
                    "source": str(source),
                    "manifest_sha256": manifest_hash,
                    "file_count": len(rows),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        _make_tree_readonly(staging)
        try:
            staging.rename(template)
        except FileExistsError:
            _remove_tree(staging)
        return template, manifest_hash


def _link_asset_tree(template: Path, game_dir: Path) -> None:
    """Mirror the immutable asset template into `game_dir` using symlinks.

    Only Imperialism.exe and Save/ differ between attempts, so there is no reason to
    duplicate the retail assets per run: they are ~237MB, and copying them per attempt
    cost 27GB across a single session's runs (enough to fill the disk). Directories are
    created for real so the game can still write new files anywhere it likes; every
    asset file becomes a symlink into the read-only template.

    This preserves the previous behaviour rather than loosening it. The old `cp -a`
    copied the template's modes too, so per-run asset files were already 0444 and the
    game could never write through them -- a symlink into a 0444 file denies writes the
    same way, and denies them at the same place.
    """
    for source in template.rglob("*"):
        relative = source.relative_to(template)
        if relative.name == GAME_ASSET_STAMP_NAME:
            continue
        destination = game_dir / relative
        if source.is_dir():
            destination.mkdir(mode=0o755, parents=True, exist_ok=True)
            continue
        destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        destination.symlink_to(source)


def prepare_game_sandbox(
    run_dir: Path, executable: Path, fixture: Path | None = None
) -> tuple[Path, Path | None, str]:
    """Create one writable working tree backed by immutable cached retail assets."""
    template, manifest_hash = ensure_game_asset_template()
    game_dir = run_dir / "game"
    if game_dir.exists():
        raise RuntimeError(f"attempt game sandbox already exists: {game_dir}")
    game_dir.mkdir(parents=True)
    _link_asset_tree(template, game_dir)
    game_dir.chmod(0o755)
    save_dir = game_dir / "Save"
    save_dir.mkdir(mode=0o755)

    sandbox_executable = game_dir / "Imperialism.exe"
    shutil.copy2(executable, sandbox_executable)
    sandbox_executable.chmod(0o555)
    linker_map = executable.with_suffix(".map")
    if linker_map.is_file():
        shutil.copy2(linker_map, sandbox_executable.with_suffix(".map"))

    staged_fixture = None
    if fixture is not None:
        fixture_dir = run_dir / "fixtures"
        fixture_dir.mkdir()
        staged_fixture = fixture_dir / fixture.name
        shutil.copy2(fixture, staged_fixture)
        staged_fixture.chmod(0o444)
    return game_dir, staged_fixture, manifest_hash


def runtime_provenance(
    executable: Path, asset_manifest_sha256: str, display: str | None,
    fixture: Path | None = None,
) -> dict[str, object]:
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    wine_version = subprocess.run(
        ["wine", "--version"], capture_output=True, text=True, check=True
    ).stdout.strip()
    return {
        "git_commit": commit,
        "runtime_executable": file_identity(executable),
        "original_executable": file_identity(original_executable()),
        "wine_version": wine_version,
        "retail_asset_manifest_sha256": asset_manifest_sha256,
        "display_mode": os.environ.get("IMPERIALISM_RUNTIME_DISPLAY", "virtual"),
        "display": display or os.environ.get("DISPLAY"),
        "fixture": file_identity(fixture) if fixture is not None else None,
    }


def shut_down_wine_prefix(environment: dict[str, str]) -> None:
    subprocess.run(["wineserver", "-k"], env=environment, check=False, capture_output=True)
    subprocess.run(
        ["wineserver", "--wait"], env=environment, check=False, capture_output=True, timeout=60
    )
