# ---------------------------------------------------------------------------
# recovery — slice discovery and Mac evidence.
# ---------------------------------------------------------------------------

[private]
[group('recovery')]
slice-discovery class address:
  uv run python -m tools.workflow.slice_discovery "{{class}}" --address "{{address}}"

# MUTATES: vendor/macos_codewarrior/evidence (regenerates the vendored Mac evidence).
[private]
[doc('MUTATES: vendor/macos_codewarrior/evidence. Regenerate symbol and resource evidence from the Mac retail files')]
[group('recovery')]
mac-evidence:
  : "${MACOS_IMPERIALISM_DUMP:?Set MACOS_IMPERIALISM_DUMP in .env (Mac retail root or extracted dump dir); only needed to regenerate the vendored evidence}"
  uv run python -m tools.workflow.macos_evidence \
    --dump-dir "{{macos_dump}}" \
    --workspace "{{macos_workspace}}"
  uv run python -m tools.workflow.macos_resource_evidence \
    --source "{{macos_dump}}" \
    --workspace "{{macos_workspace}}"

[private]
[doc('MUTATES: vendor/macos_codewarrior/evidence/resources. Regenerate the Mac UI resource oracle')]
[group('recovery')]
mac-resource-evidence source=macos_dump:
  uv run python -m tools.workflow.macos_resource_evidence \
    --source "{{source}}" \
    --workspace "{{macos_workspace}}"

[private]
[group('recovery')]
mac-evidence-check:
  uv run python -m tools.workflow.macos_evidence \
    --workspace "{{macos_workspace}}" \
    --check
  uv run python -m tools.workflow.macos_resource_evidence \
    --workspace "{{macos_workspace}}" \
    --check

[private]
[group('recovery')]
mac-resource-evidence-check:
  uv run python -m tools.workflow.macos_resource_evidence \
    --workspace "{{macos_workspace}}" \
    --check
