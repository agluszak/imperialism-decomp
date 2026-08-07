set shell := ["bash", "-eu", "-o", "pipefail", "-c"]
set dotenv-load := true

# Project constants. These are not machine-specific; edit here if they ever change.
target := "IMPERIALISM"
build_dir := "build-msvc500"
runtime_test_build_dir := "build-runtime-tests"
docker_image := "imperialism-msvc500"
lint_build_dir := "build-clang"
runtime_lint_build_dir := "build-clang-runtime"
lint_warning_test_build_dir := "build-clang-warning-test"
class_discovery_classes := "TGreatPower,TAutoGreatPower"

# The Ghidra project is vendored in-repo; only GHIDRA_INSTALL_DIR is machine-specific (.env).
# Exported so every recipe (and the pyghidra tools) use the vendored project authoritatively.
# Do NOT set GHIDRA_PROJECT_NAME/PROGRAM_NAME in .env — these exports are the source of truth.
# GHIDRA_PROJECT_DIR may be overridden in .env for one case only: a git worktree under a
# dot-directory (e.g. .claude/worktrees/...), whose path Ghidra's ProjectLocator rejects
# ("Path element starting with '.' is not permitted"). Point it at any dot-free directory
# and `just restore-project` recreates the live project there from the vendored .gzf.
export GHIDRA_PROGRAM_NAME := "Imperialism.exe"
export GHIDRA_PROJECT_DIR := env_var_or_default("GHIDRA_PROJECT_DIR", justfile_directory() / "vendor/ghidra")
export GHIDRA_PROJECT_NAME := "imperialism-decomp"

# External, machine-specific: the extracted macOS CodeWarrior dump dir. Only needed to
# REGENERATE Mac evidence (already vendored under vendor/macos_codewarrior/evidence).
macos_dump := env_var_or_default("MACOS_IMPERIALISM_DUMP", "")
macos_workspace := env_var_or_default("MACOS_CODEWARRIOR_WORKSPACE", justfile_directory() / "vendor/macos_codewarrior")

# Transitional aliases for renamed targets (see docs/workflows.md).

default:
  @just --list

# Private: fail fast (with a clear message) if the machine-specific Ghidra install
# path is missing. Ghidra recipes depend on this instead of repeating the guard.
_require-ghidra-install:
  : "${GHIDRA_INSTALL_DIR:?Set GHIDRA_INSTALL_DIR in .env}"

# baseline-update group — targets that REWRITE committed baselines/configs.
# Extracted into a module to start the justfile-modularization (8mo.19); just's
# `import` shares scope, so the surface (`just --list`) is unchanged.
import 'just/baseline-update.just'

# Per-group recipe modules (8mo.19). `import` shares a flat namespace, so
# cross-module dependencies, variables, and `just --list` output are unchanged.
import 'just/agent.just'
import 'just/sync.just'
import 'just/build.just'
import 'just/debug.just'
import 'just/runtime.just'
import 'just/compare.just'
import 'just/ghidra.just'
import 'just/gates.just'
import 'just/rewrite.just'
import 'just/recovery.just'
import 'just/analysis.just'
import 'just/setup.just'
# Compare callee-cleaned stack bytes across all paired original/recompiled functions.
ret-cleanup-audit *args:
    uv run python -m tools.workflow.ret_cleanup_audit {{args}}
