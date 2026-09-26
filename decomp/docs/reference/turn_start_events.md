# Turn-start event ownership and dispatch

`TGreatPower+0x90c` owns a list of `TTurnStartEvent` objects. It is initialized with a
`TList` at `0x4d8cc0`, receives events through `AddTurnStartEvent` (`0x4daa50`), and frees
remaining payloads and the list during `Free` (`0x4d9160`). The field is named
`turnStartEvents`; the former `missionNodeQueue` name and `TMission*` casts described a
different object hierarchy.

The Mac CodeWarrior symbols establish the names
`TGreatPower::DisplayTurnStartEvents()`, `TTurnStartEvent::Execute()` and
`TLandSaleEvent::Execute()`. Windows instructions establish their ABI and behavior:

- `0x4daa80` iterates the list in order. At `0x4daaad`, it calls each object's vtable
  slot `+0x28`, then at `0x4daad0` calls the list's `FreePayloads` slot `+0x54`.
- `TTurnStartEvent` vtable `0x653d90+0x28` holds ILT `0x406d52`, which jumps to the
  empty `Execute` body at `0x4e6610`.
- `TLandSaleEvent` vtable `0x653290+0x28` holds ILT `0x401307`, which jumps to
  `Execute` at `0x4e6740`. This method displays the land-sale message and centers the
  map. It does not restore a nation's independence, as its former name suggested.
- `TSimMgr::AdvanceGlobalTurnStateMachine` (`0x57da70`) calls the nation's display
  method when returning to the map.

The two concrete producers are the competing developer-order resolution in `TCivMgr`
and the `'star'`/`'land'` receive path in `TMultiplayerMgr`. Both initialize a
`TLandSaleEvent` and transfer it through `AddTurnStartEvent`. The proxy override at
`0x540c70` sends the event to the remote player and immediately frees the local object;
it does not insert into the local queue. The event size, fields, vtable order, append
order, and execute-all-before-free ordering remain unchanged.

## Pointer returned by the archive

For save versions greater than `0x0e`, `TGreatPower::ReadFrom` (`0x4d92e0`) reads the
list metadata, a four-byte count, and that many object references. Retail instructions
at `0x4d99da` take the address of a local **pointer**, and `0x4d99de` initializes its
whole four-byte storage to zero. The stream's `ReadObject` slot fills that storage.
When its return byte is nonzero, `0x4d99f5` reloads the pointer and `0x4d99f9` passes
it to `AddTail`. The queue receiver is reloaded from `[ESI+0x90c]` after each
object read at `0x4d99ef`, rather than retained across the stream callback.

The reconstruction passed the address of a one-byte flag and then appended a null
pointer. This could overwrite adjacent local storage and discarded the loaded object.
It now receives a `TTurnStartEvent*` and transfers that exact pointer to the owning
list. `WriteTo` (`0x4d9c70`) continues to emit the four-byte count and ordered object
references through the same stream API. No new serialization format is introduced.

The retail runtime-class descriptors at `0x6536b8` and `0x6536d0` both have schema
`0xffff`: these are dynamically creatable, non-serializable MFC classes. A newly
encountered event cannot be written through the ordinary `CArchive` class-record path.
That limitation is preserved; there are no invented event serializers or metadata
changes. Consequently, the pointer correction is supported by the retail instructions,
not by claiming a successful save/load of a populated event queue.

## Runtime coverage

The existing `return_to_map_clears_notice_queues` native case appends two real, inert
`TTurnStartEvent` objects to the active nation's queue after its initial save-backed
snapshot. It verifies insertion order, calls the production display method, and checks
that the queue is empty before its final snapshot. The base event's empty `Execute`
avoids a modal or world-state mutation, and neither snapshot attempts to serialize the
non-serializable objects. This exercises the real append, virtual dispatch, and owned
payload cleanup paths. It does not exercise the archive pointer-read branch.
