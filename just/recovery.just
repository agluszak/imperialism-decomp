# ---------------------------------------------------------------------------
# recovery — class/slice discovery and Mac evidence.
# Imported by the root justfile (flat namespace: shared variables/recipes work
# across modules). Recipe text is moved verbatim so `just --list` is unchanged.
# ---------------------------------------------------------------------------

[doc('MUTATES: regenerate the committed Mac resource reference graph')]
[group('recovery')]
mac-resource-xrefs-update:
  uv run python -m tools.workflow.mac_resource_xrefs --write

[doc('MUTATES: regenerate the committed Mac widget payload differential report')]
[group('recovery')]
mac-payload-diff-update:
  uv run python -m tools.workflow.mac_payload_diff --write

[doc('MUTATES: regenerate the committed Mac-to-Windows string crosswalk')]
[group('recovery')]
mac-string-crosswalk-update:
  uv run python -m tools.workflow.mac_string_crosswalk --write

[doc('MUTATES: regenerate the committed UI platform-delta report')]
[group('recovery')]
ui-platform-diff-update:
  uv run python -m tools.workflow.ui_platform_diff --write

# ---------------------------------------------------------------------------
# recovery — class/slice discovery and Mac evidence.
# ---------------------------------------------------------------------------

[group('recovery')]
class-discovery classes='':
  discovery_classes="{{class_discovery_classes}}"; \
  if [[ -n "{{classes}}" ]]; then discovery_classes="{{classes}}"; fi; \
  uv run python -m tools.workflow.class_discovery \
    --classes "$discovery_classes"

[group('recovery')]
slice-discovery class address:
  uv run python -m tools.workflow.slice_discovery "{{class}}" --address "{{address}}"

# MUTATES: vendor/macos_codewarrior/evidence (regenerates the vendored Mac evidence).
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

[doc('MUTATES: vendor/macos_codewarrior/evidence/resources. Regenerate the Mac UI resource oracle')]
[group('recovery')]
mac-resource-evidence source=macos_dump:
  uv run python -m tools.workflow.macos_resource_evidence \
    --source "{{source}}" \
    --workspace "{{macos_workspace}}"

[group('recovery')]
mac-evidence-check:
  uv run python -m tools.workflow.macos_evidence \
    --workspace "{{macos_workspace}}" \
    --check
  uv run python -m tools.workflow.macos_resource_evidence \
    --workspace "{{macos_workspace}}" \
    --check

[group('recovery')]
mac-resource-evidence-check:
  uv run python -m tools.workflow.macos_resource_evidence \
    --workspace "{{macos_workspace}}" \
    --check

# Attach FUNCTION markers to the ordinary destructors that below-100% scalar
# deleting destructors call (decoded from the original binary, ILT hop chased).
# Dry-run by default; pass --apply to edit source.
[doc('Claim ordinary-destructor addresses on their manual definitions')]
[group('recovery')]
add-destructor-markers *args:
  uv run python -m tools.workflow.add_destructor_markers {{args}}
