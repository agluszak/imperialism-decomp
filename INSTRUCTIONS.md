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
40. QuickDraw color state primitive: `SetQuickDrawFillColor(int)` (`0x495000`) is a tiny FPO helper and should be owned in `quickdraw_surface.cpp`, not called through no-arg stub casts. It writes `g_Quick_Draw_Color_State_006950FC`, `*(g_pActiveQuickDrawSurfaceContext + 0x28)`, and `g_uQuickDrawCurrentColor`, and matches 100% when callers push the explicit color argument.
41. Wrapped-map QuickDraw overlay (`0x596100`) is an EH-RAII body that still wants FPO on. Its stack arg is a record/context pointer, not a scalar tile ordinal: the dispatch-mode branch reads `arg + 0x24`, and the slot `0x1c0` query fills local wrapped tile coordinates plus a dispatch context used by slots `0x1c4/0x1cc/0x1d0/0x1d4`. Keep those virtual dispatches behind generated facades while class ownership is provisional.
42. Scoped QuickDraw render wrappers (`thunk_ConstructScopedMapQuickDrawContext` / `thunk_DestroyScopedMapQuickDrawContext`) are a second RAII family distinct from `QuickDrawSurfaceGuard`. Model them with a local guard object and generated vcall facades for render/update slots; `TTransFocusAnimation::RenderFocusAnimationFrameWithScopedQuickDraw` (`0x4a0770`) reached 71.19% from a stub with this shape. Keep the render target (`this+0x04`) as a provisional field until constructor/vptr evidence proves the owning class.
43. `ScopedMapQuickDrawContextGuard` uses a 24-byte stack object (`int storage[6]`), even when Ghidra sometimes shows `local_24[20]`. The 24-byte layout matches the EH-frame stack size across the compact animation wrappers: `0x4a0190` reached 81.69%, `0x49fde0` reached 75.86%, and `0x4a0770` improved 71.19% -> 84.75% after changing the shared guard from 20 to 24 bytes.
44. If a Ghidra name says `Destruct...` but the body has no free flag, no base/member teardown, no `operator delete`, and instead advances timers/renders/invalidates UI, rename the manual implementation to behavioral semantics and leave the old exported name as source evidence. Example: `0x49fde0` is now `AdvanceOneTimeAnimationFrameAndInvalidateTargetRect`, while `symbols.csv` still records the stale `TOneTimeAnimation::DestructTOneTimeAnimationAndMaybeFree` label.
45. Use the shared `RECT`, `CopyRect`, and `OffsetRect` declarations in `include/game/ui_widget_shared.h` for UI/QuickDraw slices. Do not introduce new per-file `tagRECT`/`RECT` structs unless a different binary layout is proven.
46. For Mac-guided input handlers, preserve hidden stack args before tuning locals. `TTwoPicSlider::TrackMouse` evidence maps Windows `0x56e640` to a `ret 0x0c` method shape: the phase is the first visible stack arg, while the y-coordinate record used by `*(short *)(arg + 4)` is a later stack arg. Modeling that stack shape moved the function from stub to 45.63%.
47. If a promoted UI body clearly owns `ecx=this` and returns with stack cleanup, prefer a real provisional class method over a free `__fastcall` bridge once the hidden args are known. `TCityProductionViewLayout::RenderViewIntoPrimaryRenderContextWithTemporaryClip(int,int)` (`0x4bc9b0`) confirms this pattern: a stale no-arg Ghidra prototype actually has `ret 8`, and the method form keeps class recovery cleaner than a bridge.
48. For generated vcall facades, verify pushed arguments in `reccmp --verbose` before trusting a no-arg Ghidra prototype. `TDiplomacyMapViewLayout::RenderDiplomacyLegendSurfaceAndPresent` (`0x4f6170`) showed slot `0x1e0` takes `(terrainIndex, labelSelector)`, runtime slot `0x34` takes selector `0x3f`, and strategic-map slot `0x98` takes the short at `this+0x98`; adding those stack args moved the slice from 38.28% to 46.30%.
49. If Ghidra assigns a helper to the surrounding class but callsites pass a repeated interior object as `ecx`, split out a provisional subobject type. In the diplomacy legend palette path, `this+0x1eac` behaves as a `DiplomacyMaskBufferRun` object for `0x4f66c0`, while `this+0x2078` is a separate packed-color run advanced by 0x30 bytes per nation.
50. A `thiscall` on a global-pointer manager (`mov ecx,[global]; push arg; call thunk`) is best modeled as a real method on a typed struct pointing at that global, not a `__fastcall(ptr, edx_dummy, arg)` cast (the dummy `edx` load pollutes the matched body). `ModuleLibraryCacheState* g_pModuleLibraryCacheState` (`0x6a134c`) with `LoadBmpResourceById`/`ReleaseRecordByHandle` reproduces the exact `mov ecx,[0x6a134c]; push id; call` shape in the caller; only the call target (bridge vs thunk) differs. The bridge method body keeps the unavoidable ABI dummy out of the matched function.
51. The Ghidra decompiler can mis-model a tail thiscall thunk as a flat cdecl call. For `0x4f6bd0` it showed `AppendPackedColorDword(*(ctx+4), palette)` as 2-arg cdecl, but the listing is thiscall: `ecx = this+0x2078+idx*0x30`, then `push palette; push surface`. Always confirm packed-color/append calls against the instruction listing, not the decompiler, before choosing cdecl-thunk vs member-call shape.
52. When the original anchors a surface object through `context+4` (e.g. `[esi+0x1c]`, `[esi+4]`, `[esi]` all relative to one pointer), express every access through a single `int* ctx = (int*)(global+4)` local rather than splitting `context` and `context+4`. Splitting them adds a spill slot (`sub esp` grows) and tends to flip the esi/edi binding. Even after unifying, MSVC500 may still swap `context+4`<->`this` between esi/edi; that swap cascades through pixel loops and is the dominant residual mismatch when branch/loop shape already matches (`0x4f6bd0`: 0% -> 25.30%).
53. `SetUiResourceContextTagWord` (`0x4270e0`, thunk `0x402aa4`) is `__thiscall(int* slot, value)` doing `*slot = value`; in the diplomacy mask-run path it fills the very stack slot that is then passed as `BlitMonochromeMaskBytePatternToSurface`'s `paletteByte` arg, with the palette sign-extended (`movsx edx,ax`). Modeling it as a no-arg call (current mode-1/mode-4/`0x4f6b10`) loses that `movsx`+stack-slot sequence; a typed tag-slot struct method is the faithful shape and would lift all three at once.
54. MSVC500 can `fatal error C1001 (INTERNAL COMPILER ERROR)` under FPO (`optimize("y")`) on loops with several parallel induction cursors plus pointer dereferences. Collapse to a single integer induction variable and compute the per-iteration offsets inline (`base + i*stride`); the optimizer re-applies strength reduction and the codegen still matches well. Seen on `0x4f71a0` (three cursors -> one index).
55. Reading a global flag/byte into a *local* once and writing the modified value back to the literal address (`*(char*)0xADDR = local | 1`) matches MSVC500 better than caching a pointer to it (`char* p = (char*)0xADDR; *p |= 1`), which emits an extra `mov reg,0xADDR`. The original reads the global directly (`mov al,[0xADDR]`). Lifted `0x4f5e00` 38% -> 43%.
56. For backend functions exported with free-function names but decompiled with `in_ECX`, verify the listing with `just ghidra-listing 0xADDR` before choosing a signature. `DiplomacyTurnStateManager` queries at `0x4ef540`/`0x4ef600`/`0x4ef650` are real `ecx=this` methods with stack cleanup (`ret 8` or `ret 4`) even though symbols describe free functions taking an explicit manager pointer.
57. Treat Ghidra `__fastcall` labels on backend/ILT dispatchers as suspect unless `edx` is live. Follow the listing and thunk chain: `0x4f0db0` is a global wrapper (`mov ecx,[0x6a43d0]; jmp 0x406aaf`), while `0x406aaf` is the real method-style thunk into `DiplomacyTurnStateManager::ProcessQueuedWarTransitions`. Modeling the wrapper and method thunk separately matched both at 100%.
58. In `DiplomacyTurnStateManager`, let vtable slot bodies define the matrix bands and return widths, not old facade names. Slot `0x68` (`0x4f19c0`) reads the `+0x79c` short matrix and returns full `EAX` standing-tier constants; changing the facade from `short` to `int` made the method 100%. Slot `0x70` (`0x4f1b10`) reads the `+0xbbe` relation-code matrix and returns `AX`.
59. For broad backend setters, accept an initial low similarity score when the function unlocks class layout and downstream slots. `DiplomacyTurnStateManager` slot `0x74` (`0x4f1b70`) currently matches only 9.31%, but its shape pass proves symmetric `+0xbbe` relation-code writes, `+0xfe0` turn-stamp updates, `+0x1402` side-effect writes, and the nation/terrain/manager notification slots needed by the UI and queued-war slice. Record that evidence and move to adjacent validators before micro-tuning.

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
