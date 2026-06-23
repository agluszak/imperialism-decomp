---
name: just-lint-enforces-override
description: just lint (real clang) gives compile-time override checking that MSVC500 cannot; run it on vtable/override work
metadata:
  type: feedback
---

`override` is a no-op macro under MSVC500 (`include/compat.h`: `#define override`), so
the primary `just build` gives **zero** compile-time protection: a derived method whose
name/signature drifts from the base virtual silently becomes a *new* vtable slot instead
of an override, shifting the layout — and the build stays green.

**`just lint`** builds with real clang (where `override` is a true keyword) and is the
only check that catches this as a compile error. It also surfaces other real C++ issues
the MSVC500 build hides.

**Why:** I shipped a TWindow slot 0x60-0x63 desync (`vmethod_009x` vs the renamed
`ReturnFromUiSlot6x`) that broke the TGameWindow vtable; `just vtable` caught the symptom
but `just lint` would have caught the cause up front. User correction: "`just lint` gives
compile time protection."

**How to apply:** after any base-virtual rename or derived-override edit, run `just lint`
before trusting `just vtable`/`just build`. Baseline `-Wmissing-prototypes` noise on
autogen stubs is expected; scan for `error:` and `override`. See heuristics note in
[[tview-vtable-slot-port-recipe]] context and [[model-real-classes-not-callconv-casts]].
