#!/usr/bin/env bash
set -euo pipefail

# Reproducible phase-1 FID pipeline:
# 1) import selected .lib COFF members
# 2) analyze imported object programs
# 3) populate a single fidb library
#
# Usage:
#   new_scripts/run_msvc500_phase1_fid_pipeline.sh \
#     [ghidra_home] [project_name] [subset_dir] [fidb_out]

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GHIDRA_HOME="${1:-/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC}"
PROJECT_NAME="${2:-msvc500-fid-import-v5}"
SUBSET_DIR="${3:-$ROOT_DIR/fid/msvc500_phase1_nodebug_subset}"
FIDB_OUT="${4:-$ROOT_DIR/fid/fidbs/msvc500_phase1_nodebug.fidb}"
COMMON_SYMBOLS="$GHIDRA_HOME/Ghidra/Features/FunctionID/data/common_symbols_win32.txt"
LOG_DIR="$ROOT_DIR/tmp_decomp"
TS="$(date +%Y%m%d_%H%M%S)"

mkdir -p "$LOG_DIR" "$(dirname "$FIDB_OUT")"

log_step() {
  echo "[$(date +%H:%M:%S)] $*"
}

run_headless() {
  local log_file="$1"
  shift
  echo "$*" > "$log_file"
  # shellcheck disable=SC2068
  "$@" >> "$log_file" 2>&1
}

log_step "Step 1/3: import unique COFF members from subset libs"
LOG1="$LOG_DIR/fid_phase1_import_${TS}.log"
run_headless "$LOG1" \
  "$GHIDRA_HOME/support/analyzeHeadless" "$ROOT_DIR" "$PROJECT_NAME" \
  -scriptPath "$ROOT_DIR/scripts" \
  -postScript ImportMSLibsNoPromptUnique.java /msvc500_phase1_unique/libs "$SUBSET_DIR" \
  -noanalysis

log_step "Step 2/3: analyze imported object programs"
LOG2="$LOG_DIR/fid_phase1_analyze_${TS}.log"
run_headless "$LOG2" \
  "$GHIDRA_HOME/support/analyzeHeadless" "$ROOT_DIR" "$PROJECT_NAME/msvc500_phase1_unique/libs" \
  -scriptPath "$ROOT_DIR/scripts:$GHIDRA_HOME/Ghidra/Features/FunctionID/ghidra_scripts" \
  -process -recursive \
  -postScript FunctionIDHeadlessPostscript.java

log_step "Step 3/3: create and populate fidb"
rm -f "$FIDB_OUT"
LOG3="$LOG_DIR/fid_phase1_populate_${TS}.log"
run_headless "$LOG3" \
  "$GHIDRA_HOME/support/analyzeHeadless" "$ROOT_DIR" "$PROJECT_NAME" \
  -scriptPath "$ROOT_DIR/scripts" \
  -postScript CreateSingleFidLibraryNoPrompt.java \
    "$FIDB_OUT" /msvc500_phase1_unique/libs msvc500 phase1 nodebug x86:LE:32:default "$COMMON_SYMBOLS" \
  -noanalysis

log_step "Pipeline done."
log_step "FIDB: $FIDB_OUT"
log_step "Logs:"
echo "  $LOG1"
echo "  $LOG2"
echo "  $LOG3"
