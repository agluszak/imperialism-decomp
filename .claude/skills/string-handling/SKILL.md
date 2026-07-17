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
  Use `just string-oracle` / `just ghidra-strings` to read the real content.
- **`LPCSTR` casts**: passing a `CString` where the original passed `char*` needs the
  `(char*)(LPCSTR)` double cast the repo already uses — copy an existing call site.

## Field notes

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
