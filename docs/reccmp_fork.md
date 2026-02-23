# reccmp Fork Notes

Local fork location:
- `/home/agluszak/code/personal/reccmp`

Current usage in this repo:
1. Primary CLI is invoked through project `uv` environment (`uv run reccmp-*`).
2. Build detection:
   - `uv run reccmp-project detect --what recompiled`
3. Full compare:
   - `uv run reccmp-reccmp --target IMPERIALISM`
4. Targeted verbose compare:
   - `uv run reccmp-reccmp --target IMPERIALISM --verbose 0x005882F0`

Operational notes:
1. Re-run `reccmp-project detect` after each rebuild.
2. Tiny wrappers can be folded/aliased by compiler/linker; targeted compare may map to unexpected symbols.
3. Keep `reccmp-user.yml` local and gitignored; commit `reccmp-project.yml` only.
