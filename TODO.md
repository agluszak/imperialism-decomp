# Imperialism RE TODO (Active Queue)

History/logs moved to `agent_2.md`.

## Active (max 3)
- [ ] Struct/enum propagation in hot dispatch/state lanes
  - done: full 26-command turn-instruction typing pass (including `pric/prov/tbar/tclr/coun`) with `STurnInstruction_*` structs.
  - done: city-building hover/control coordinate DAT cluster dehardcoded (`0x0069619c..0x006961da`) to typed `ushort` globals.
  - next: propagate enum parameter types in command/event handlers where param names are still generic (`param_*`, `arg*`) by first normalizing signatures.
  - next: continue high-xref global struct typing in remaining runtime windows outside resolved locale/stream lanes.

- [ ] Class attachment + ABI normalization follow-up
  - done: attached 166 global typed-`this` methods into class namespaces (safe typed-first-param batch).
  - next: recover more class ownership by retyping global `__thiscall` first params from `void*` to concrete class pointers, then rerun typed-attach sweep.
  - next: normalize method signatures after ownership moves where hidden-`this`/stack params are still generic.

- [ ] Runtime-pointer state class extraction follow-up
  - continue field-semantics naming in runtime state classes (`TCViewOwnedBuffer*`, `TRuntimeHeapBufferOwnerState_0066FA68`, `TModuleLibraryCacheTableState*`, etc.).
  - finish remaining anonymous ranges in `TCViewOwnedBufferRegistryState_00648560` (`0x68..0x6b`, `0x78..0x8f`) once usage evidence is clearer.
  - propagate typed class pointers into remaining ctor/create helpers and wrapper thunks.

## Queued
- [ ] Tooling consolidation lane (no throwaway scripts)
  - use `uv run impk` as the only execution path for maintained commands.
  - when a needed command is missing, port it to `src/imperialism_re/commands/` + `command_catalog.yaml` before use.
  - avoid parallel command variants that duplicate behavior; extend existing maintained commands with flags.

- [ ] Nation-metrics dispatch table lane (`0x0066d9f0..0x0066da18`)
  - recover owner/consumer sites that index this table (direct code/data range refs currently zero).
  - apply `/Imperialism/ENationMetricsDispatchSlot` to selector parameters when callsites are identified.
  - continue de-orphaning nearby `0x005b97xx..0x005ba1xx` helpers with behavior-based names.

- [ ] TView/TControl/TradeControl class-contract alignment
  - recover/label missing vtable ownership evidence for `TradeControl` (or confirm abstract/no-concrete-vtbl status).
  - normalize method ABI where virtual slots clearly require `this` semantics.
  - propagate stable field names from verified `TView`/`TControl` layout into ghidra types.

- [ ] Targeted state/command enum propagation in post-class lanes
  - apply enum types to hot handlers now moved into runtime/state classes where command/state constants are still raw integers.
