# ---------------------------------------------------------------------------
# compare — reccmp scoring, stats, session planning (read-only).
# Imported by the root justfile (flat namespace: shared variables/recipes work
# across modules). Recipe text is moved verbatim so `just --list` is unchanged.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# compare — reccmp scoring, stats, session planning (read-only).
# ---------------------------------------------------------------------------

# Compare functions against the original.
#   just compare                  -> full reccmp summary (all functions)
#   just compare 0xADDR           -> verbose asm diff for one function
#   just compare 0xA 0xB 0xC ...  -> batch score table (single PDB parse)
#   just compare --file src/game/foo.cpp [more.cpp]  -> score every // FUNCTION in the file(s)
# Batch/file mode runs one `reccmp --json` parse (~4s for all ~9600 funcs) instead
# of one cold PDB parse per address.
[doc('Score vs original: no args=all, 0xADDR=asm diff, multiple addrs/--file=batch')]
[group('compare')]
compare *args:
  #!/usr/bin/env bash
  set -euo pipefail
  args=({{args}})
  if [[ ${#args[@]} -eq 0 ]]; then
    (cd "{{build_dir}}" && PYTHONPATH=.. uv run python -m tools.reccmp.compare_cli --target "{{target}}")
  elif [[ ${#args[@]} -eq 1 && "${args[0]}" != "--file" ]]; then
    (cd "{{build_dir}}" && PYTHONPATH=.. uv run python -m tools.reccmp.compare_cli --target "{{target}}" --verbose "${args[0]}")
  else
    uv run python -m tools.reccmp.compare_batch --target "{{target}}" --build-dir "{{build_dir}}" {{args}}
  fi

# Score every // FUNCTION marker in src/game/<Class>.cpp (single PDB parse).
[group('compare')]
compare-class cls:
  just compare --file "src/game/{{cls}}.cpp"

# Compare vtable layouts against the original.
#   just vtable          -> all vtables
#   just vtable TSound   -> only vtables whose name contains "TSound"
#   just vtable -v        -> pass through reccmp-vtable flags (e.g. --verbose)
[doc('Compare vtable layouts vs original; optional class-name filter')]
[group('compare')]
vtable *args:
  #!/usr/bin/env bash
  set -euo pipefail
  args=({{args}})
  extra=()
  filter_name=""
  if [[ ${#args[@]} -gt 0 && "${args[0]}" != -* ]]; then
    filter_name="${args[0]}"
    extra=(--filter "${filter_name}")
    args=("${args[@]:1}")
  fi
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  set +e
  (cd "{{build_dir}}" && uv run reccmp-vtable --target "{{target}}" "${extra[@]}" "${args[@]}") | tee "$tmp"
  rc=${PIPESTATUS[0]}
  set -e
  # reccmp-vtable prints "Vtables found: 0.\n100% match." when the name filter matches no
  # reccmp-paired vtable. That "100% match" is vacuous (nothing was compared) and has
  # misled us into thinking unmarked/unpaired classes were verified. Turn it into a failure.
  if grep -qE "Vtables found: 0\." "$tmp"; then
    echo "" >&2
    if [[ -n "$filter_name" ]]; then
      echo "ERROR: no reccmp-paired vtable matched '${filter_name}' — 0 vtables compared." >&2
      echo "       The '100% match' above is vacuous, not a verification." >&2
      echo "       Cause: the class has no '// VTABLE: IMPERIALISM 0x...' marker, or its" >&2
      echo "       marked vtable is not being paired by reccmp (name/address mismatch)." >&2
    else
      echo "ERROR: 0 vtables were compared — the '100% match' above is vacuous." >&2
    fi
    exit 1
  fi
  exit "$rc"

# Compare global data values against the original.
#   just datacmp          -> all globals (only ones with a problem)
#   just datacmp -a       -> include matching globals; pass through reccmp-datacmp flags
[group('compare')]
datacmp *args:
  (cd "{{build_dir}}" && uv run reccmp-datacmp --target "{{target}}" {{args}})

# Compare symbol locations (functions, vtables, data) between original and recompiled.
#   just roadmap          -> full roadmap
#   just roadmap -v       -> pass through reccmp-roadmap flags
[group('compare')]
roadmap *args:
  (cd "{{build_dir}}" && uv run python ../tools/reccmp/typed_roadmap.py --target "{{target}}" {{args}})

# Translate original-binary addresses to recomp addresses and back (for winedbg
# breakpoints, crash addresses, etc.). Direction auto-detected; result cached next
# to the build until the binary/PDB changes.
#   just addr 0x491cc0 [0x...]
[doc('orig<->recomp address lookup with name + match % (cached reccmp parse)')]
[group('compare')]
addr *args:
  uv run python -m tools.reccmp.addr_translate --target "{{target}}" --build-dir "{{build_dir}}" {{args}}

# Compare the stack layout of a single near-matching function.
#   just stackcmp 0xADDR
[group('compare')]
stackcmp addr *args:
  (cd "{{build_dir}}" && uv run reccmp-stackcmp --target "{{target}}" {{args}} "{{addr}}")

# Interpret reccmp's trusted semantic proof or first structured machine-level
# divergence with Imperialism-specific source/layout advice.
# `just triage 0xADDR [...]` or `--file SRC.cpp`.
[group('compare')]
triage *args:
  uv run python -m tools.reccmp.triage --target "{{target}}" --build-dir "{{build_dir}}" {{args}}

# Batch stack-layout triage: run reccmp-stackcmp over near-match functions and
# rank layout suspects. `just stackcmp-triage [--min 0.4] [--max 0.999] [--limit 12]`.
[group('compare')]
stackcmp-triage *args:
  uv run python -m tools.reccmp.stackcmp_triage --target "{{target}}" --build-dir "{{build_dir}}" {{args}}

[doc('Mass behavioural-divergence sweep: join reccmp verdicts with call-contract verdicts, rank by defect class')]
[group('compare')]
sweep *args:
  uv run python -m tools.reccmp.semantic_sweep --target "{{target}}" --build-dir "{{build_dir}}" {{args}}

[group('compare')]
stats *args:
  uv run python -m tools.reccmp.progress_stats --target "{{target}}" --build-dir "{{build_dir}}" --detect-recompiled {{args}}

[doc('Compare original/recomp high-p-code call contracts for all manual functions or selected addresses/files')]
[group('compare')]
semantic-compare *args:
  uv run python -m tools.semantic_calls --target "{{target}}" --build-dir "{{build_dir}}" compare {{args}}

[doc('Summarize the current fingerprint-matched high-p-code call-contract report')]
[group('compare')]
semantic-stats:
  uv run python -m tools.semantic_calls --target "{{target}}" --build-dir "{{build_dir}}" stats

[group('compare')]
inventory:
  uv run python -m tools.reccmp.library_inventory --json-out "{{build_dir}}/library_inventory.json"

# Rank the next porting targets and write build-msvc500/next_loop.{md,json}.
# Read-only by default; pass --refresh-ignore to also rewrite reccmp-project.yml
# ignore lists (previously the default — see Hard Rule 14).
[doc('Rank next porting targets -> build-msvc500/next_loop.md; --refresh-ignore also rewrites ignore lists')]
[group('compare')]
session-loop pick='8' top='50' min_size='1' *args:
  uv run python -m tools.reccmp.session_loop --target "{{target}}" --pick "{{pick}}" --top "{{top}}" --min-size "{{min_size}}" {{args}}

# Core-impact candidate ranking (the third session-loop artifact) as a first-class
# target. `just core-impact [--top N] [--min-size N]`.
[group('compare')]
core-impact *args:
  uv run python -m tools.reccmp.core_impact_ranking --target "{{target}}" --top 50 --min-size 1 {{args}}

[doc('Mine reccmp asm diffs for orig-address<->recomp-symbol global pairs (read-only report)')]
[group('compare')]
global-xref-oracle *args:
  uv run python -m tools.reccmp.global_xref_oracle {{args}}

# Evidence-only categorization of original-only zero-size DATA roadmap rows.
[group('compare')]
zero-size-data-audit:
  uv run python -m tools.reccmp.zero_size_data_audit
