---
name: decomp-loop
description: Core function-porting loop for the Imperialism decomp — promote a Ghidra function to compile-safe C++, do a shape pass then a data pass, rebuild with Docker MSVC500, and compare with reccmp to raise the match score. Use whenever matching, promoting, porting, or improving the similarity of a target function/address.
---

# Decomp loop

The continuous loop for porting Ghidra functions into real, compile-safe C++ — one
function (or tightly-coupled cluster) at a time. Obey the Hard Rules and Command
Policy in `AGENTS.md`. Detailed matching tactics live in `heuristics.md` next to this
file — read it before tuning a body.

## Current objective: breadth + real shapes, NOT 100% similarity

The priority right now is **porting more functions with correct, real C++ shapes** —
real classes, real member methods, real virtual dispatch, real inheritance — not
squeezing any single function to 100%.

- **Ignore pragmas entirely.** Do **not** add `#pragma optimize`, chase FPO/frame-pointer
  differences, or tune register allocation. A body that is structurally faithful (right
  calls, right order, right receivers) at 30–60% is a *success*; move on. Frame-pointer
  (`/Oy`) and instruction-scheduling diffs are expected residual and are explicitly out
  of scope.
- **Promote to unblock.** If a body needs a callee, receiver class, global, or signature
  that isn't modeled yet, **port/declare that too** rather than inventing a hacky
  workaround (no raw `vftable[...]`, no `reinterpret_cast` to fake a calling convention,
  no `VCall_*` facade). Fix the owning class's signature from the disassembly, declare the
  real method/global, and call it for real. A correct shape that pulls in one more real
  declaration beats a self-contained fake.
- Use the score only as a *pairing sanity check* (did it pair? is the shape roughly
  right?), not a target. Don't restore-the-higher-scoring-body dances over pragma noise.

## The loop

1. **Pick one target** function (or a tightly-coupled neighbor pair). Prefer
   high-impact non-trivial bodies over tiny thunks. `just compare 0xADDR` once
   first to confirm it is a real body, not a `jmp` trampoline.
2. **Promote** the Ghidra text. Promotion copies the decompiled body out of
   `src/ghidra_autogen/<Class>.cpp` into your manual file with the `// FUNCTION:` marker
   attached, and removes the address from stub ownership so there's one owned impl.
   - `just promote src/game/<Class>.cpp --address 0x005d6b70` — raw autogen copy of one
     function. The address is the original-binary offset (the autogen marker). It appends
     the block (marker + raw `__thiscall` body) to `<Class>.cpp`; you then shape it.
   - `just promote-shaped src/game/<Class>.cpp --address 0x...` — preferred when
     `config/classes/<Class>.yml` exists: it also reshapes the `__thiscall Cls::M(Cls*
     this, …)` head into a real member signature for you.
   - `just promote-range src/game/<Class>.cpp 0xLOW 0xHIGH` — bulk-promote every owned
     function in an address range (a whole class slice) in one pass.
   - Targeting: the file should be the owning class's `src/game/<Class>.cpp` (Hard Rule 7).
     If the autogen reads against `jmp`-thunk/alias names, run `just normalize-autogen`
     first so the promoted body references real symbols.
   - After a bulk promote, if `just decomplint` reports `function_out_of_order`:
     `uv run python -m tools.workflow.reorder_marked_functions <file.cpp>`.
   - **Promote-to-unblock is allowed and encouraged:** if the target calls a sibling/base
     method or another class's function that's still a stub, promote *that* too (into its
     own owning `<Class>.cpp`) so the call is real. Promoting a callee adds/moves a marker
     → that's exactly when you must re-run sync-ownership + regen-stubs (see step 4).
3. **Shape pass** — make it compile-safe C++ that preserves the original control
   flow:
   - keep call order, branching shape, and fail-and-continue behavior from Ghidra;
   - rewrite raw `void __thiscall Foo(T* this, ...)` Ghidra blocks into real member
     methods before building (raw form breaks MSVC parsing and loses address
     pairing);
   - call vtable slots through generated facades / real virtuals, never raw
     `vftable[...]` indexing (see the `class-recovery` skill).
4. **Sync + build**:
   - `just build` — always. Use `just build`, **not** a hand-rolled `docker run`: it
     applies the exact match flags (`RelWithDebInfo`, `IMPERIALISM_LINK_MFC=ON`,
     `/Oy-,/Ob1`) and produces a fresh PDB. A wrong-flags build (e.g. plain `Release`)
     yields a tiny exe with a stale PDB and makes reccmp crash with
     `InvalidVirtualAddressError`. After deleting `build-msvc500/`, run `just detect`
     before any reccmp tool (else "missing recompiled_path").
   - `just sync-ownership` → `just regen-stubs` — **only when you added, removed, or moved
     a `// FUNCTION` marker, or changed ownership** (e.g. you promoted a new function).
     For a pure body or signature edit on an already-owned function, **skip these**:
     `regen-stubs` can downgrade hand-typed stub signatures back to generic
     `undefined ()` and break the link for unrelated files.
5. **Compare** the touched function: `just compare 0xADDR --verbose`.
6. **Data pass — optional, and only the cheap real-shape wins.** Align obvious
   `short`/`int` widths, hidden stack args, struct-return-via-hidden-pointer, and return
   contracts when they reflect the real shape. **Stop there.** Do not chase FPO,
   register allocation, or add pragmas (see "Current objective").
7. **Verify**: run `just gates` for the mechanical source-policy gates (raw-vtable,
   construction anti-patterns, marker hygiene, vtable correctness). Run `just stats` when
   the edit's blast radius could change aggregate progress.
8. **Keep and move on:** if it pairs and the shape is faithful, keep it and go to the
   next function — even at 30–60%. If it won't pair, fix the marker/ownership; if a
   receiver class genuinely can't be modeled yet, record what you learned and move on.
9. **Record the lesson**: append transferable tactics to `heuristics.md` (this skill)
   and put change-specific details, commands, score deltas, and residual risks in the
   commit message.
10. **Repeat** with the next highest-impact mismatch.

## Marker hygiene (must hold every iteration)

- `// FUNCTION: IMPERIALISM 0x...` must be immediately followed by the declaration —
  no comment or blank line between them.
- One owned implementation per address; no duplicate `// FUNCTION` for one address
  across manual files and stubs.
- Whenever you edit markers/ownership: `just sync-ownership` → `just regen-stubs` →
  `just build`.
- Both rules above are enforced mechanically by `just marker-gate` (part of
  `just gates`). Run `just gates` before committing.

## Thunks and stub signatures: never fake, always port

A free function that is still a stub (`undefined4 Foo(void)`) or reached through an ILT
jmp thunk is **not** a license to fake a signature at the callsite. Two banned shortcuts,
both of which look like progress but block real recovery:

- **Don't `reinterpret_cast` a `(void)` stub/thunk to a typed signature to call it.**
  (`reinterpret_cast<int(__cdecl*)(T*,int)>(Foo)(this, x)`.) Adjusting arg/return *types*
  of a genuinely same-convention `__cdecl(void)` thunk is technically legal (Hard Rule 9),
  but if the real target is portable, **port it** instead.
- **Don't whitelist a name in `tools/stubgen.py` to emit a typed stub.** That fakes a
  signature without a real body and is an explicit anti-pattern — do not add entries.

The correct fix when the original does `CALL <ilt-thunk>` → real target:

1. **Port the real target into its owning file** (find it via `config/function_ownership.csv`
   neighbors — sibling addresses reveal the right `<Class>.cpp`/module file), with a real
   body, `// FUNCTION:` marker, and real signature; `just sync-ownership` → `regen-stubs`.
2. **Retire the thunk completely.** reccmp auto-resolves `CALL <thunk>` → real target
   **only if the thunk has no named `config/symbols.csv` row.** A named `thunk_Foo` row
   makes reccmp compare `call thunk_Foo` vs your `call Foo` as a literal mismatch (caps the
   caller ~93%). Delete the thunk's rows from **both** `config/symbols.csv` and
   `config/thunk_map.csv`; the stub regenerates away and the caller hits 100%.
3. **Call the real function directly** from a normal header-declared prototype. Watch the
   convention: MFC `PASCAL`/`WINAPI` helpers (e.g. `CDC::FromHandle`) are `__stdcall`
   (callee cleans) — a `__cdecl` cast adds a spurious `add esp,4`.

See heuristic **12b** in `heuristics.md` for the worked example (the QuickDraw DC family).

## When a compare fails to pair

See the `quality-control` skill ("Known reccmp failure modes"): usually a misplaced
marker, a duplicate address, or a comment between marker and declaration.
