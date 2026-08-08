---
name: decompile-function
description: Recover or diagnose C++ function bodies from the Imperialism retail binary using listing-first evidence, verified calling conventions, typed data, MSVC5-compatible source, and structured reccmp feedback. Use for any function port, low-score body, callee/signature question, EH/string/FP/codegen issue, MFC collection behavior, or large-function recovery under decomp/.
---

# Decompile a function

Run from `decomp/` and obey `AGENTS.md`.

## Workflow

1. Start through `just agent-start port 0xADDR`; do not bypass its base, ownership, or claim checks.
2. Read `just ghidra listing 0xADDR`. Resolve ILT thunks to real targets. Treat names,
   decompilation, and calling conventions as provisional.
3. Run `just advice 0xADDR` and load only the references matching the observed body:

   - Always read [core-loop.md](references/core-loop.md).
   - Read [calling-conventions.md](references/calling-conventions.md) for any call, receiver, ECX/EDX,
     argument-count, or `ret N` question.
   - Read [string-handling.md](references/string-handling.md) for text, formatting, assertions,
     string-pool data, or `CDumpContext`.
   - Read [ctors-dtors-eh.md](references/ctors-dtors-eh.md) for EH frames, non-POD locals, allocation,
     constructors, destructors, or compiler cleanup helpers.
   - Read [fp-matching.md](references/fp-matching.md) for x87/float/double code or unexplained frame
     bytes around floating-point work.
   - Read [codegen-shapes.md](references/codegen-shapes.md) for loop, branch, switch, flag-byte,
     extension, or magic-division mismatches.
   - Read [data-modeling.md](references/data-modeling.md) for globals, `.data`/`.rdata`, layouts,
     offsets, widths, and field attribution.
   - Read [big-functions.md](references/big-functions.md) for bodies around 500 bytes or larger,
     giant switches, or recovery that feels too complex.
   - Read [mfc-collections.md](references/mfc-collections.md) for MFC collection-shaped fields,
     methods, and vtables.

4. Transcribe the retail structure and data in ordinary VC5-compatible C++. Prefer real types,
   methods, virtuals, construction, and ownership. Never add a symptom workaround or source-model
   bridge to chase a score.
5. Build after a coherent shape pass, then run `just triage 0xADDR`. Act only on `mismatch`; treat
   `effective` as proved and `inconclusive` as a verifier/metadata question.
6. Iterate shape, then data, then compiler-sensitive phrasing. Finish with `just agent-check`.

## Field notes

Search [loop-heuristics.md](references/loop-heuristics.md) for prior source-shape lessons. For MFC
container emission and layout cases, also search
[mfc-collection-heuristics.md](references/mfc-collection-heuristics.md). Add durable new matching
lessons to the narrowest applicable reference; keep task history in Beads and Git.
