---
name: fp-matching
description: Match floating-point codegen in the Imperialism decomp — FPU operand order, float vs double locals and constants, FDIV-through-memory vs register shapes, dead-arg-slot float temps, commutative-multiply chains, score wobble on FP leaves. Load whenever a target does float math, an FCOM/FMUL/FDIV chain mismatches, a frame is 8 bytes too big, or FP scores wobble in untouched functions.
---

# Floating-point matching

MSVC500 FP codegen is deterministic but sensitive to *where* values are homed
(register vs float-slot vs double-slot) and to expression/statement structure. Key
levers, most powerful first:

- **float vs double locals**: a `double` temp costs an 8-byte slot (`fstp qword`) and
  usually an alien frame size; original engine code almost always stores `float`.
  A `sub esp, 8` you can't account for = a double spill you introduced.
- **Which variable a temp is assigned to controls the `FSTP`.** The original often
  reuses one memory-homed variable (commonly the function's shared `result`, living
  in a dead arg slot) for every case's scratch float: `result = expr; return a /
  result;` emits `fstp [slot]; fdiv [slot]`, while a fresh local may stay on the FPU
  stack (`fxch/fdivp`). If you see store+reload in the original, assign through a
  reused variable.
- **Multiply chains follow source order with the last CALL's result live in st0**:
  `return LastCall(...) * f6 * f4 * f5;` emits `call; fmul [f6]; fmul [f4]; ...`.
  Reorder the written factors to match the original's FMUL operand sequence — the
  math is commutative, the codegen is not.
- **Explicit `static_cast<float>(...)` forces the rounding store** (`fstp dword`);
  removing or adding one is a two-line diff lever.
- **Constants are named globals** (`g_Compute_*` etc. in `global_data_tables`), and
  float/double twins of the same value are DIFFERENT constants at different addresses
  — check the operand width (`fsub qword` vs `fsub dword`) and reference the right
  one (add the missing twin rather than casting the wrong one).
- **FP wobble in untouched functions is not a regression** — commutative operand
  order can flip when a TU grows (see the score-wobble policy in AGENTS.md).
- **Let structured diagnosis decide whether FP order matters.** Run `just triage`
  before source-tuning a low raw score. `effective` with `commutative_order` means
  reccmp proved the reordered FP expression harmless (the Imperialism x87 case at
  `0x4e0590` is a representative low-score proof); stop tuning it. Only a concrete
  `mismatch` such as `memory_value` or `return_value` is actionable. `inconclusive`
  means the verifier could not decide, not that the FP source is wrong.

## Field notes

### Big matching-heavy function: use float (not double) locals to avoid an alien frame
*(ex decomp-loop note 48)*


A `double` local for a distance metric forces an 8-byte-aligned frame (`push ebp;
and esp,-8`) the original (which used `float`) never emits — storing the metric as
`float` removed the whole alien prologue on the 1073-byte
`BuildOverlaySpanRecordsFromQuadBorderLinks` (0x52cae0). Match the original's FP width.
Beyond that, a big function's score is dominated by the compiler's induction-variable
register choice, which source can't steer — expect ~30% structural and treat the
absolute aligned-byte gain as the win. (A large standalone function may live in its own
`.cpp` per §19 — but never move code between TUs to chase neighbouring
register-allocation noise; see §47.)

- **A local whose live range ends at the accumulate gets `faddp`; one that lives to
    scope end gets `fxch/fadd/fxch/fstp`.** When the original shows the four-op
    shuffle around a `sum += term` (term preserved then dropped), the source declared
    the term variable OUTSIDE the loop (`double difference;` at function scope,
    assigned per-iteration). Hoisting the declaration took 0x5362c0 from 85.7% to
    95.05%. Corollary: intermediates that never spill to memory between FP ops were
    declared `double`, not `float` — float locals force rounding stores.

  *(ex decomp-loop list-note 64)*

- **`static_cast<int>(int_expr * float_global + int_field)` reproduces MSVC5
    `fild;fmul[global];fiadd[field];call __ftol`.** int*float promotes via FILD+FMUL, the
    trailing `+ int_field` becomes FIADD (int memory operand), and the outer cast to int
    is `__ftol`. Use this shape for int<-float score/diffusion math instead of a manual
    ftol() bridge.

  *(ex decomp-loop list-note 82)*

### The dead-arg-slot assignment is one global, source-immune allocator choice
*(ex decomp-loop note 113)*


MSVC500 reuses a dead argument's stack slot for one address-taken local. WHICH local gets
it is a whole-function allocation decision that (in 8 tested configurations) could not be
flipped from source: scratch-pointer helpers, by-value inline params, fn-scope vs
block-scope vs union temps, and declaration reordering all left the same winner (the swap
temp), while the original gave the slot to a later list-count. Worse, the choice is
chaotic: bracing ONE late count block reshuffled the entire frame and cost 9pp elsewhere.
Practical protocol: (a) find the config that matches the MOST slots and freeze it;
(b) A/B one change at a time — a probe build after each single edit, never batch two frame
knobs; (c) when only the slot-winner differs, stop — that's the ceiling; document it at the
function. Related fact: locals allocate by FIRST USE (argument evaluation is right-to-left,
so `f(&a,&b)` allocates b first); declaration position does not matter.

- **The shared uninitialized `float result` of a switch-heavy scorer doubles as each case's
     scratch temp.** 0x4e8750: every case's stored float temp (case-1/2 denominator, case-3/4
     product, case-6 ratio) lands in the SAME arg-slot the merged `return result;` tail FLDs.
     Port shape: declare `float result;` once, `switch` with per-case `return expr / result`
     after assigning `result = <temp>`, cases that fall through `break` into a single trailing
     `return result;` — the dead default path reading garbage is original behaviour, keep it.

  *(ex decomp-loop list-note 115)*
