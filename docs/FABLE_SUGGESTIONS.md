# Structural problems & proposed fixes (Fable, 2026-07-01)

Big-picture issues identified while porting the UI foundation classes, in impact
order. Each entry: the problem, the evidence, the proposed fix, expected payoff.

## 1. Header-inline ctors/dtors — a systemic match ceiling

**Problem.** The original source defined the T-hierarchy's constructors and
destructors *inside the class bodies in headers* (implicitly `inline`). MSVC500
therefore inlines them into `CreateObject`, into derived dtor chains, and at
`new T()` callsites. Our reconstruction defines them out-of-line in `.cpp`, so
the same sites compile to a `call` instead of inlined code.

**Evidence.**
- `TIncludeView::CreateObject` (0x48cc40), `TWindow::CreateObject` (0x48d090),
  `TControl::CreateObject` (0x48e430) all contain their class's ctor fully
  inlined (registry `AddHead` CPlex code and all); our macro-generated
  `CreateObject` calls the out-of-line ctor → pairs at ~36%.
- `TIncludeView::~TIncludeView` (0x48ce70) contains `~TView` fully inlined
  (vptr rewrite to 0x649858, child-list delete, +0x58 CString dtor); ours would
  emit `call TView::~TView`.

**Fix.** One careful experiment on TView: move `TView::~TView` (and later the
ctor) into `TView.h` as a class-body definition, then force the out-of-line copy
that the `// FUNCTION: 0x0048a9d0` marker needs (candidates: keep one TU where
inlining fails naturally via the scalar-deleting-dtor SYNTHETIC, or check MSVC5's
behavior for address-taken/virtual-dtor emission). Verify 0x48a9d0 still pairs,
then measure 0x48ce70/0x48cc40-style scores. If it works, roll out
hierarchy-wide.

**Payoff.** Hundreds of ctor/dtor-adjacent functions across ~400 classes are
currently capped at ~36–70% by this one modeling decision.

## 2. MSVC5 per-TU twins — a reccmp expressiveness gap

**Problem.** A header-inline function gets a fresh out-of-line copy in every
translation unit that needs one, and the 1997 linker performed no identical-code
folding — so the exe contains N byte-identical copies at N addresses. Our source
defines the function once; reccmp pairs strictly one orig address to one recomp
symbol, so N−1 copies are permanently counted "unported" and accrete junk names.

**Evidence.** `TView::~TView`: 0x48a9d0 (paired) plus byte-identical twins
0x48cb00, 0x48ec30, 0x48ee00 (verified instruction-for-instruction); TView's
scalar deleting destructor twin at 0x48cad0. These carried fictional curated
names ("TScroller::CreateTScrollerInstance", "TButton::CreateTButtonInstance")
that misdirected multiple sessions.

**Fix.** Extend the vendored reccmp fork with a twin/alias annotation (e.g.
`// TWIN: IMPERIALISM 0xADDR` following a `// FUNCTION:`-owned definition, or a
multi-address marker) that pairs additional original addresses against the same
recomp symbol and scores each independently.

**Payoff.** Converts a whole category of fake-unported functions into measured
coverage; removes a standing source of misleading names. The four TView twins
are the tip — every header-inline function in a 400-class hierarchy potentially
has copies.

## 3. Exploit the RTTI oracle fully (Mac evidence is second-class)

**Problem.** The binary's MFC `CRuntimeClass` descriptors are intact,
compiler-emitted ground truth — true class name, **object size**, base-class
edge, `CreateObject` address — and until now nothing checked our curated data
against them. Meanwhile inheritance/layout work has leaned on the Mac
CodeWarrior dump, which is a *different build for a different platform*:
useful as a name/signature hint, second-class as evidence. The Windows RTTI
supersedes it wherever both speak.

**Done already** (commit aaea549d): `just rtti-oracle` +
`config/rtti_class_oracle.csv` (471 descriptors, 403 game classes); 326 wrong
symbols.csv names fixed; 307 `CreateObject` SYNTHETIC claims applied.

**Remaining fixes.**
- **Size gate:** cross-check every modeled class (`sizeof` via ASSERT_SIZE or a
  compile-time probe) against the oracle's `object_size`; report mismatches.
  Catches layout errors mechanically instead of via crash archaeology.
- **Base-edge import:** the `m_pBaseClass` chain gives the entire
  single-inheritance tree; diff it against our modeled `class X : public Y`
  edges and against `IMPLEMENT_DYNCREATE(X, Y)` second arguments.
- **GetRuntimeClass claims:** each descriptor's class has a trivial
  `MOV EAX, <descriptor>; RET` slot-0 override (e.g. 0x48cb90 → TScroller's
  0x6495b8); these are macro-generated and mass-claimable the same way
  CreateObject was.

## 4. Ghidra database code gaps distort scores and searches

**Problem.** Chunks of real code are undefined in the Ghidra DB (no function, no
instructions): switch bodies behind jump tables, functions reached only via
vtables/thunks. Consequences: xrefs and decompiles come back empty, and reccmp
cannot disassemble the *original* side past an indirect `jmp`, so byte-equivalent
ports score absurdly low.

**Evidence.** `CMcWindow::OnWindowStateMsg468` (0x493800) scored 26% while being
byte-identical. RESOLVED 2026-07-02: not a reccmp-disassembler issue — Ghidra had
defined the switch's *case bodies* as standalone functions (junk symbols.csv rows at
0x493819/29/39 + a paired autogen stub), which clamped reccmp's max_size window to
0x19 bytes. Deleting the rows + regen-stubs took it to 98%. reccmp's InstructGen
handles in-function jump tables correctly (verified standalone). The general fix for
this class of junk (case-body pseudo-functions in the Ghidra DB) belongs to the
gap-repair pass below. 0x5742b0 and several CMcWindow handlers were invisible to
`ghidra-listing`/xrefs until raw-disasm'd.

**Fix.** A gap-scan pass: walk `int3`-padded boundaries, vtable slot targets,
ILT jmp targets, and message-map `pfn`s; `createFunction` each undefined target
in the Ghidra DB; re-export the project archive. Optionally teach the reccmp
fork to follow jump tables on the original side.

## 5. Tooling odds and ends

- **Batch compare:** every `just compare 0xADDR` re-parses the PDB (~seconds).
  A multi-address mode (`compare 0xA 0xB 0xC`, one parse) would tighten the
  port-verify loop dramatically. (`compare-class` exists but is per-file.)
- **`gen-class` is dead code:** it requires `config/classes/<Class>.yml`
  manifests and `config/classes/` does not exist. Either seed manifests from the
  RTTI oracle (name, size, base are all known now) or retire the tool.
- **`sync-ownership` is add-only:** removing a marker leaves a stale ownership
  row that silently suppresses stub regeneration for that address (hit twice
  this session). It should reconcile deletions, or at least warn.
- **symbols.csv fragility:** line 1 is a header row; a resort moved it to EOF
  and silently broke vtable resolution (364/379 vtables "mismatched" until
  restored). The loaders should reject/relocate a misplaced header, and a
  round-trip check belongs in `just gates`.
- **Curated-name provenance:** symbols.csv names carry no confidence/provenance
  marker, so RTTI-verified truth and old guesses look identical. A provenance
  column (rtti/mac/manual/ghidra-auto) would let tools trust accordingly.
