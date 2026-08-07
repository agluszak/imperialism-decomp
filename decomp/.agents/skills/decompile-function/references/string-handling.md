---
name: string-handling
description: Match string-heavy Imperialism functions — CString construction/destruction/concatenation, string-pool globals, CDumpContext/operator<< overloads, assert and format strings. Load whenever a target function builds text, touches CString locals or members, references string literals, or looks "too messy to port because of strings" — string-heavy functions are ported now, never postponed; the shapes below are mechanical.
---

# String handling

String-heavy functions look noisy in a diff but their codegen is highly regular.
Never postpone a function because it "does a lot of string work" — identify which of
the shapes below it uses and transcribe them.

## Core shapes

- **CString locals mean an EH frame.** Every non-trivial `CString` local adds an EH
  state and a dtor call on every exit path; the `push -1 / push __ehhandler` prologue
  and `mov [esp+..], state` stores are compiler output that appears automatically
  when you declare the locals — do not model them by hand. See the `ctors-dtors-eh`
  skill for state-number matching.
- **A named CString local vs an unnamed temp are different codegen.**
  `CString t(x); target = t;` re-materializes `t`'s buffer with `lea` and places it
  in a dead-arg slot; `target = CString(x);`-style unnamed temps reuse the ctor's
  EAX. Pick whichever the original shows (see field note below).
- **`operator+` chains**: `*out += "\n     " + zoneName` compiles to nested
  `CString::operator+` calls with temporaries — write the natural expression; MSVC500
  emits the temp dance itself.
- **`CDumpContext <<` picks overloads by exact type.** `dc << value` resolves to a
  specific `operator<<(unsigned long / long / unsigned int / LPCSTR / CObject&)`
  overload; a mismatched overload is a one-line fix with a `static_cast` at the use
  site (TLongintList::Dump needed `static_cast<unsigned long>(ordinal)` and
  `static_cast<unsigned int>(value)` to hit the original's pair).
- **String literals live in named pools.** Repeated literals are shared `.data`
  globals (`s_sz*_00xxxxxx` in `global_data_tables`); a "mislabeled empty global"
  operand in a diff often really holds the string (e.g. `" "` behind a junk name).
  Reference the named global, not a duplicate literal, or the operand won't pair.
  Use `just ghidra string-oracle` (or `just strings-for-function <addr>`) to read the real content.
- **`LPCSTR` casts**: a `CString` passed through a string ellipsis must be converted
  explicitly (`static_cast<LPCSTR>(text)`) so VC5 pushes the character pointer rather
  than the four-byte object. Ordinary typed parameters should keep their natural
  conversion. `just cstring-gate` checks the known stack-indexed template expanders.
- **Mutable buffers are paired operations.** Every `GetBuffer` or
  `GetBufferSetLength` path needs the evidence-matching `ReleaseBuffer`; do not request
  a mutable buffer just to obtain an input `const char*`. `just cstring-gate` rejects
  mechanically visible unpaired acquisitions and direct CString/CStringData internals.

## Field notes

### Keep CString ownership checks outside MFC internals
*(2026-07, `cstring-ownership-audit` and `cstring-runtime-probe`)*

Audit game-owned records with the VC5 layout oracle: snapshot physical field spans,
reject raw game-source copies crossing an embedded or owned CString field, and review
each `TObject::ShallowClone` path against its retail listing. Do not reconstruct
`CStringData`, touch `m_pchData`, or implement MFC reference counting. Exercise the
remaining ABI/lifetime assumptions through the public API in a standalone VC5/MFC 4.2
probe (`just cstring-runtime-probe`), including the four-byte object, empty value,
copy-on-write, buffer mutation, embedded arrays, return-by-value, and EH unwinding.

### Low-disk template expansion needs an explicit first replacement argument
*(2026-07, WarnLowDiskSpaceAndConfirmContinue 0x415760)*

The localized resource `0x2763:0x19` contains `[1:number]`. The retail listing formats
the free-megabyte count into a CString, then pushes that CString's character pointer
after the template pointer before calling `scanBracketExpressions`. The faithful call
is `scanBracketExpressions(ctx, &out, static_cast<LPCSTR>(templateText),
static_cast<LPCSTR>(formattedNumber))`. A three-argument call silently makes the callee
read an unintended caller stack slot; `templateText.GetBuffer(0)` is also wrong because
the callee only reads the template and no matching `ReleaseBuffer` follows.

### Missing assert file/line args are a cheap, systematic score win
*(ex decomp-loop note 111)*


`TemporarilyClearAndRestoreUiInvalidationFlag(...)` (0x0049d620) is variadic: called bare `()`
it's a flag toggler, but the retail asserts push the Mac source path + line before it (via the
ILT thunk 0x004057a4). MANY ported nil-pointer failure paths call it with NO args, so the
original's `MessageBox` + `assert(sourcePath, line)` sequence never gets emitted — a fixed
block of missing instructions that caps the function below 100%. Fix: pass the real path/line,
e.g. `TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UCountry.cpp", 0xa0e)`.
Find the exact string+line from the callee's decompile (`func_0x004057a4(s_D__Ambit_..._cpp, N)`);
reccmp pairs the string literal by content, so a plain literal is enough (no kAddr needed). The
grep that finds candidates:
`for f in $(grep -rl 'TemporarilyClearAndRestoreUiInvalidationFlag();' src/game); do awk '/GAME_FAIL_NIL_POINTER\(\);/{p=NR} /...Flag\(\);/&&NR==p+1{print FILENAME":"NR}' $f; done`
Took UpdateOrderEntryAvailabilityByConnectedRegionMask 98%->100% and (with a counter-reread
tweak) TUnit::RegisterUnitOrderWithOwnerManager 91%->100% in one line each. There are ~12 more
bare no-arg calls across src/game (TButton/TCity/TDlgWindow/TEventHandler/TMacViewMgr/TNetMgr…)
— sweep them when hunting cheap wins. NOTE the file often differs per function
(UCountry.cpp / UCountryAuto.cpp / UUnit.cpp / UNavy.cpp) — always read the callee, don't assume.

- **CString temp placement: a named local (`CString t(x); target = t;`) re-materializes its
     address with `lea` and can land in a dead ARG slot; the unnamed `target = CString(x)` form
     reuses the ctor's EAX return and gets elided by our compiler where MSVC5 kept a real copy.**
     If the orig shows ctor→`lea` reload→operator=→dtor, use a named local; if it shows
     ctor→`push eax` directly, use the unnamed temp (0x50ec90 tuningOverride vs 0x5dfd70
     fullPath). Wrapping in an extra `{}` block to move the dtors shifts EH-state numbering and
     usually scores worse — pick the local form, not the block form.

  *(ex decomp-loop list-note 107)*

### Variadic `[N]`-template substitutors index the caller's vararg stack, not a real table
*(2026-07, FilterStringByCharacterTypeFlag4AndAppend 0x49a7f0, 70%)*

A string function whose decompile shows `auStackY_bN[param[i]]` used as a `char*` — where
`auStackY_bN` is a large *uninitialized* stack array below ESP — is not a real table: it is
the compiler indexing the **caller's argument list** with a pre-biased base. The asm is
`MOVSX ECX,byte[fmt+i]; MOV EDX,[ESP + ECX*4 - 0xNN]` where the `-0xNN` displacement biases
a `&fmt`-relative base by `-'0'*4`. So `[N]` (N an ASCII digit) selects the N-th trailing
string argument counting from `fmt` itself: source is `(&fmt)[fmt[i] - '0']` (compiler folds
`-'0'` into the base displacement, emitting exactly the biased indexed load). Model the
function `Foo(int unusedLead, CString* out, char* fmt, ...)`; `out` is a caller-provided
**return slot** copy-CONSTRUCTED (0x6057a7), not assigned — use `new (out) CString(result)`
(genuine placement into a caller buffer, allowed). `isdigit`: the retail body emits
`CALL _isdigit`, so `#include <ctype.h>` then `#undef isdigit` to force the function form (the
macro inlines the `__pctype` table test and drops the call); a bare `extern "C" int isdigit(int)`
fails the clang-cl lint with `-Winconsistent-dllimport`.

### Error/assert modal reporters are pure `Format` + `operator+=` chains — 99-100% attainable
*(2026-07, FormatAndAssignTurnStateSharedTextFromTemplate 0x5d48c0, 99%→exact)*

A function with N `CString` locals, `CString::Format` (0x5ff15e) calls, and a long
`operator+=` run building one message, ending in `TViewMgr::ModalMessage`, is mechanical.
Keys: (a) format the number locals FIRST (declare them, `.Format(g_szDecimalFormat, n)`),
THEN declare the accumulator `CString` — matches the original's "3 ctors, 3 Formats, 1 ctor"
emission order; declaring all four up front runs the 4th ctor too early. (b) `operator+=`
overload is auto-selected: literal/`char*` → 0x605cce (LPCSTR), `CString&` → 0x605d0a. (c)
Read the exact separator/format string globals from the PE `.data`/`.rdata` (manual section
walk: `va-ImageBase - section.VirtualAddress + section.PointerToRawData`) — `just ghidra
string-oracle` only lists sole-referenced strings and caps output, missing shared 1-char
separators like `","`/`"'"`/`" at "`. reccmp pairs literals by content, so inline them. (d)
`ModalMessage(message_by_value, g_ptSomePlacement)` — the pass-by-value CString emits the copy
ctor naturally; add the `g_pt*ModalMessage` POINT global as `{0,0}` in global_data_tables.cpp.
The residual (if any) is one library CString-ctor ILT thunk (0x4076b7) — not worth touching a
shared thunk.
