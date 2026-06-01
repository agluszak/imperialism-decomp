# Imperialism Decomp Instructions

## Hard Rules

1. No inline assembly.
2. Use `just` targets for normal workflow (`tooling-check`, `build`, `detect`, `compare`, `stats`, `promote`, `sync-ownership`, `regen-stubs`).
3. `// FUNCTION: IMPERIALISM 0x...` must be immediately followed by the function declaration.
4. Do not place any other comment or blank line between `// FUNCTION` and the declaration.
5. One owned implementation per address in manual source.
6. No duplicate `// FUNCTION` for the same address across manual files and stubs.
7. If you edit markers/ownership, run:
   1. `just sync-ownership`
   2. `just regen-stubs`
   3. `just build`
8. Keep naming from Ghidra unless there is a concrete semantic reason to rename.
9. Do not rename for style-only reasons.
10. Keep class-owned functions in `src/game/<ClassName>.cpp`.
11. Keep non-class/global trade code in `src/game/trade_screen.cpp`.
12. For free-function bridges in this toolchain, prefer `__fastcall`; avoid `__thiscall` casts in free function pointer typedefs.
13. If repeated `this + offset` / `reinterpret_cast` access maps to a stable class region, promote it to a typed class field (or typed view struct) instead of keeping cast-helper indirection.
14. Keep external thunk declarations in the generic repo form (`undefined4 ... (void)`) and use typed local function-pointer casts at callsites; changing declaration signatures directly can cause MSVC name-mangling linker breaks.
15. MSVC500 keeps `for` loop variables in function scope; avoid redeclaring the same loop variable name later in the same function.
16. For vtable calls in manual code, do not introduce local `typedef ...Fn` + `reinterpret_cast` blocks; call through generated facades in `include/game/generated/vcall_facades.h`.
17. Keep low-level slot-cast mechanics isolated in `include/game/vcall_runtime.h`; gameplay code should not index vtables directly.
18. If `config/vtable_slots.csv` changes, regenerate with `just gen-vcall-facades` before build/compare.
19. `config/vtable_slots.csv` is the single source of truth for generated vcall wrappers project-wide.
20. The raw-vtable gate (`just vtable-gate`) must pass; do not introduce new raw-vtable patterns in files that are not already baseline-tracked.
21. `just session-loop` mutates `reccmp-project.yml` ignore lists; run it only when you explicitly want to rewrite ignore configuration.

## Promotion Loop

1. Pick one function or a tight neighbor pair.
2. Promote with `just promote ...` (or `just promote-range ...`).
3. Make compile-safe C++ first; do not micro-tune immediately.
4. Run ownership/stub sync.
5. Run `just build`, `just detect`, `just compare 0xADDR`.
6. Run `just compare-canaries` after each accepted iteration to ensure no unresolved regression debt on tracked anchors.
7. If score moves, keep it and move on; if stuck, move to next function.

## Similarity Improvement Notes

1. Run `just compare 0xADDR` once before heavy rewrite to confirm whether the target is a real body or a thunk/trampoline.
2. If diff shows `jmp OtherFunction`, implement a call-through wrapper first (and keep heavy logic in the destination function).
3. In deserializer functions, do not reuse pointer params as scalar counts; use return values from stream-vtable reads for loop bounds.
4. Preserve original short/int loop semantics (`short` counts, `static_cast<short>(idx)` loop exits) when Ghidra shape clearly indicates truncation.
5. When Ghidra shows `InitializeSharedStringRefFromEmpty` / `ReleaseSharedStringRefIfNotEmpty` envelopes, keep them in manual code if they are in the same function.
6. Avoid adding defensive null-guards in hot legacy deserialization paths unless evidence shows they exist in the original; extra guards usually hurt similarity.
7. Keep cast-heavy vtable/thunk calls in small typed helper wrappers; keep target function bodies mostly cast-free so shape/data edits stay maintainable.
8. `just promote` output is raw Ghidra text; convert it immediately to compile-safe member-method C++ and then run `just sync-ownership`, `just regen-stubs`, and `just build` before comparing.
9. If a readability simplification causes a meaningful similarity drop on a target function, restore the higher-scoring body shape and keep the cleanup in helpers/typed views instead.
10. Newly promoted GHIDRA blocks with `void __thiscall ... (TGreatPower* this, ...)` must be rewritten to real member signatures before build; leaving raw form causes MSVC parse failures and address pairing loss.
11. When a class method name collides with an existing global symbol, use explicit `this->Method(...)` in bridges and verify link output; unresolved externals often come from accidental global resolution.
12. Prefer typed global-slot helpers (`ReadNationStateSlot`, `ReadSecondaryNationStateSlot`, `ReadTerrainDescriptorSlot`) over raw address cursor loops; this avoids pointer-step bugs and keeps ownership loops maintainable.
13. For serialized stream/message blocks, preserve aggregate read/write sizes from Ghidra (`0x0C`, `0x180`, `0x70`, etc.) instead of expanding into element-by-element loops unless the original clearly does so.
14. When a wrapper function in Ghidra feeds queue state from stream records, keep the refill stage (stream read marker + conditional queue push) in place even if a simplified version compiles; omitting it can hold similarity in the low 20s/30s range.
15. If `reccmp --verbose` shows `ret 0x10`/`ret 0x0C` but C++ emits `ret 8`/`ret 4`, treat it as a signature mismatch first (missing stack args) before micro-tuning locals.
16. When Ghidra shows `extraout_AL` driving a branch after a call, model that call as returning a flag (or use a typed call cast at callsite); pre-checking with a different helper usually destroys call shape.
17. For nation-eligibility checks, pass the real manager from `0x006A43E0` and use a `char`/flag return in C++; `int` wrappers with null `ecx` often emit the wrong branch shape.
18. For UI dispatch wrappers, avoid adding defensive null/function-pointer guards unless present in the original shape; load globals only in the taken branch to keep register/stack flow closer.
19. For turn-event dispatcher thunks, verify both calling convention and payload order; several paths are `__stdcall` with prepended `this->nationSlot`, and using `__cdecl` (or omitting the nation arg) introduces stack-cleanup/call-shape drift.
20. For tiny getter-like functions, trust `reccmp --verbose` on `ret` size and field offset: if original shows `ret 4` and `this+0xXYZ`, align method signature/arg count and use an explicit typed offset view when class-field offsets are still fluid.
21. If a function clearly needs `this+0xXYZ` but current class members compile to a different offset, use a local typed offset-view struct for that function and keep class-wide field renames for a dedicated layout pass.
22. In hot matching functions, avoid introducing helper calls for simple field reads (`ref->data_ptr`, `header->text_length`); prefer direct typed overlay access in-place so MSVC emits memory loads instead of extra call sites.
23. If a Ghidra `void` function still sets `AL` on the success/fallthrough path, test a narrow `char`/flag return signature before tuning locals; keeping observable return flow can prevent MSVC from deleting score comparisons.
24. For single-JMP thunk helpers with misleading no-arg prototypes, inspect the callsite stack setup. Preserve pushed scalar args in the local typed cast even when the autogenerated thunk declaration says `void`.
25. Before assigning helpers or fields to a class, run a local vertical slice (`just slice-discovery <Class> 0xADDR`) and separate evidence into `this` fields, actual vcall wrappers, and global/helper calls. A helper called from a class method is not class membership evidence by itself.
26. Treat class recovery as an MSVC staged reconstruction problem: vftables and vptr writes first, then typed `this` structs, then inheritance only when structural evidence exists. Do not infer base edges from names alone.
27. Persist class-recovery observations as `ClassCandidate` evidence (`class_candidate.json`) before making class/layout edits; empty unknowns are better than speculative edges or fields.
28. Class labels are provisional. For uncertain clusters, run `slice-discovery` with a synthetic candidate label plus explicit `--vtable`/`--classdesc` anchors and record vptr writes/allocation sizes before trusting current symbol names.
29. Scalar deleting destructors/lifetime wrappers often return `this` even when surrounding names look like `void` helpers; if original shows `mov eax, esi` before `ret 4`, model the wrapper as returning the object pointer.
30. In MSVC factory constructors, vptr write order can differ from the reusable base-state constructor. Preserve observed factory ordering (base construction, field initialization, then final vptr write) even if a sibling constructor uses vptr first.
31. For compiler-generated Relative Calls to Incremental Link Table (ILT) thunks in the original binary, mapping the correct ILT thunk addresses in symbols.csv rather than the final implementation addresses keeps call-sites aligned.
32. To avoid demangling failures due to anonymous namespace hash names in parameter types (which cause Wine to fail to demangle and prevent pairing), clean up parameter types of thunks to global base types (like TView* instead of anonymous structs).
33. When calling a member function of a global class instance (such as g_pUiRuntimeContext->GetActiveNationId()) where the original assembly loads the instance pointer in ecx, declare the method as a standard member of that class and map its address in symbols.csv to ensure the compiler generates the correct register-loading instructions.
34. Mac CodeWarrior evidence lives outside git under `/home/agluszak/code/decomp/imperialism_knowledge/macos_codewarrior`; use `just mac-evidence` and treat it as a name/signature oracle only. It must not directly assign Windows addresses, calling conventions, vtables, or inheritance.
35. When Mac evidence identifies a method signature with hidden stack args (for example `DoPostCreate(TDocument*)` or `AdjustForZero(short, short)`), test the signature before tuning locals. Correct stack cleanup and member-call shape can improve matching more than expression rewrites.
36. For class families with repeated Mac methods (`DrawAmt`, `DoPostCreate`, `DrawMax`), attach method names across siblings once the Windows bodies and vtable neighborhoods support the role; keep inheritance/base edges provisional until vptr/offset evidence proves them.
37. EH-RAII guard pattern (high-yield, architectural): if the original function starts with the MSVC C++ EH prologue (`push -1; push __ehhandler; mov fs:[0]`) and immediately does `lea ecx,[esp+X]; call <ctor>`, it is wrapping a **local RAII guard object**. To reproduce the EH frame + ctor/dtor calls, model a stack `struct Guard { <field(s)>; Guard(); ~Guard(); };` with the ctor/dtor owning the impl addresses, and let the destructor run implicitly at scope exit (do NOT call it explicitly, and do NOT call the acquire/release as free `(void)` functions). MSVC only emits the EH frame for an object with a non-trivial, implicitly-invoked destructor. `tmp_decomp/eh_functions.json` enumerates all 966 EH-prologue functions; cluster by leading ctor to find guard families (shared-string temps dominate at 138, but those already use the `StringShared` dtor and thus already have their frame — the lever is for acquire/release pairs still written as free functions, e.g. the QuickDraw surface guard `0x497320`/`0x497390`).
38. FPO (`#pragma optimize("y", on)`) is target-dependent — measure both ways:
    - For **leaf / simple helper** functions (few locals, no EH), the original is
      FPO and matching it needs FPO on; e.g. `SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty`
      (`0x495310`) went 53% -> **100%** purely by enabling FPO. Put such helpers in a
      file with `#pragma optimize("y", on)` at the top (see `src/game/quickdraw_surface.cpp`).
    - For **complex EH-RAII bodies** (e.g. the amount-bar `DrawAmt`), forcing FPO makes
      MSVC promote `ebx`/`ebp` as scratch (`xor ebx,ebx; cmp esi,ebx`) and diverge MORE
      than the kept-frame (`/Oy-`) build. Leave those non-FPO.
    - When a helper reuses a computed pointer offset (original shows `add eax,0x14; jne`
      then `[eax+4]`), mirror that reuse in C++ (`int slot = *p + 0x14; ... [slot+4]`)
      instead of recomputing; recomputation drops the score.
39. Original intra-module calls route through ILT thunks (`0x40xxxx jmp <impl>`). reccmp does not always auto-follow them in verbose diffs (a real call shows as `<OFFSETn>` against our named target); confirm the true target by disassembling the thunk in Ghidra before assuming a callsite mismatch.

## Known reccmp Failure Modes

1. `Failed to find a match at address 0x...`:
   1. Check marker placement (rule #3/#4).
   2. Check duplicate address ownership (rule #5/#6).
   3. Run `just sync-ownership` + `just regen-stubs` + `just detect`.
2. `Dropped duplicate address ...`:
   1. Same address is still annotated in a stub shard or another manual file.
3. Compare name looks like a sentence/comment:
   1. A comment line is between marker and declaration.
4. Build breaks on `__thiscall` in free typedef:
   1. Replace with `__fastcall` bridge shape.

## Logging Policy

1. Keep execution details in `docs/worklog.md`.
2. Update `docs/control_plane.md` only when strategy changes.
3. Do not duplicate the same long status in multiple places.
