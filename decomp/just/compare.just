[doc('Ghidriff comparison: authored addresses/names, --file, --changed, or --all')]
[group('compare')]
compare *args:
  uv run python -m tools.workflow.msvc_build_lock --lock "{{build_dir}}/.msvc-build.lock" -- uv run python -m tools.reccmp.compare_batch --target "{{target}}" --build-dir "{{build_dir}}" {{args}}

[doc('Saved comparison counts, call queue, and optional merge-base delta')]
[group('compare')]
compare-report *args:
  uv run python -m tools.reccmp.report {{args}}

[doc('Compare vtable layouts vs original; optional class-name filter')]
[group('compare')]
vtable *args:
  #!/usr/bin/env bash
  set -euo pipefail
  args=({{args}})
  extra=()
  if [[ ${#args[@]} -gt 0 && "${args[0]}" != -* ]]; then
    extra=(--filter "${args[0]}")
    args=("${args[@]:1}")
  fi
  (cd "{{build_dir}}" && uv run reccmp-vtable --target "{{target}}" "${extra[@]}" "${args[@]}")

[group('compare')]
datacmp *args:
  (cd "{{build_dir}}" && uv run reccmp-datacmp --target "{{target}}" {{args}})

[doc('Translate original/recomp entry addresses through the paired entity catalog')]
[group('compare')]
addr *args:
  uv run python -m tools.reccmp.addr_translate --target "{{target}}" --build-dir "{{build_dir}}" {{args}}
