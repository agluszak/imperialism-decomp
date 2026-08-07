# Cursor Cloud environment notes

Environment prep (install `uv`/`just`/Docker/host-`wine`, `uv sync`, and the one-time
`just docker-build` of the `imperialism-msvc500` image) is already done by the VM
snapshot + startup update script; only the non-obvious notes below matter. To
re-provision a fresh host from scratch (system packages, Ghidra, original binary,
first build), run `scripts/bootstrap.sh` — it is the one-time bootstrap; the
per-session refresh stays just `uv sync`.

- **Start the Docker daemon before any build.** `dockerd` is not auto-started on a
  fresh session. Start it once per session (it needs the docker-in-docker workaround
  already configured in `/etc/docker/daemon.json` = `fuse-overlayfs`):
  `sudo dockerd >/tmp/dockerd.log 2>&1 &` (or run it in a tmux session). Then
  `sudo docker info` should report `Storage Driver: fuse-overlayfs`.
- **`just` calls bare `docker`.** User `ubuntu` is in the `docker` group, so a
  *newly started* shell can run `docker`/`just build` without `sudo`. Within a shell
  that started before the group took effect, wrap the command:
  `sg docker -c 'just build'`.
- **The original binary is present in the snapshot** at `orig/Imperialism.exe` (sha256
  `6afab8495db715fd9e719cffa74abe5ede4dd763428ff65d73be4edf16c9e691`), wired via the
  gitignored `.env` (`ORIGINAL_BINARY=/workspace/orig/Imperialism.exe`) and
  `reccmp-user.yml` (`targets.IMPERIALISM.path`). Do **not** run `just bootstrap-reccmp`
  — it refuses to overwrite the committed `reccmp-project.yml`; hand-write/keep
  `reccmp-user.yml` instead (workflows §0). These three files are gitignored and persist
  in the snapshot.
- **reccmp needs host-side `wine`** (installed): the compare/stats/roadmap tools run
  `cvdump.exe` via `wine`/`winepath` to parse the recompiled PDB. Prefix long compare
  runs with `WINEDEBUG=-all` to silence Wine chatter.
- **What works:** the whole loop — `just tooling-check`, `just test`, `just build`,
  `just detect`, `just resource-check`, `just compare 0xADDR` / `--file`, `just stats`,
  `just vtable`, `just datacmp`, `just gates`, `just precommit`, and the source-only gates.
  (`just compare`/`--file` exits non-zero when any listed function is below 100% — that
  is a score signal, not a setup failure.)
- **Still blocked:** running the game (`just run`/`debug`/`screenshot`) needs the full
  retail install (a `Data/` folder next to the exe), which is not present — only the exe
  was supplied.
- **Ghidra targets work in cloud** (`ghidra-*`, `ghidra-apply-source`, `refresh-inventory`,
  `restore-project`). The snapshot ships Ghidra 12.1.2 at `/opt/ghidra_12.1.2_PUBLIC`, the
  matching `.env` `GHIDRA_INSTALL_DIR`, and the LFS-pulled project export
  (`vendor/ghidra/exports/Imperialism.gzf`, sha256 in the sibling `.sha256`). The one gotcha
  is that a fresh shell does **not** inherit `GHIDRA_INSTALL_DIR` — export it before any
  `just ghidra-*` target: `export GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.2_PUBLIC` (or
  `set -a; . ./.env; set +a`). Run `just restore-project` once per session to load the
  program into the Ghidra project (`Program already present` means it's ready); then
  `just ghidra decompile 0xADDR`, `just ghidra listing`, etc. all work.
