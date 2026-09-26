# Naval ship links and order ownership

`TShip` is a naval unit on the global ship roster. Its constructor inserts it at
`g_pNavyPrimaryOrderListHead`, and `Free` removes it. A ship may also appear in a
task force's `shipList` and a navy mission's `orderList24`. Each list owns its
separately allocated `TMapOrderChildLinkNode` cells; neither list owns a ship
merely because it has a link to one. `TShip` and `TTaskForce` derive directly
from `TObject`. Their overlapping numeric offsets do not establish another
shared base class.

## Why both link chains contain ships

Windows instructions establish the receiver and payload type, independently of
the old field names:

- `TShip::DemandExclusiveTaskForce` (`0x5503a0`) reads the receiver's nation
  short at `+0x14` and zone pointer at `+0x08`, then inserts that same receiver
  into a task force's `shipList`. `+0x14` is a pointer in `TTaskForce`, so the
  receiver cannot be a task force.
- `TShip::SetTaskForce` (`0x551220`) writes selection at `+0x34`, inside the
  0x38-byte `TShip` and beyond the 0x34-byte `TTaskForce`.
- `TNavyMission::AcceptReenforcement` (`0x536780`) inserts its `TShip*`
  argument into `orderList24`; `RejectConstituent` removes the same pointer.
  Mission serialization stores roster indices for those ships, and reads them
  back through `TShip::GetNth`.
- `TMapOrderChildLinkNode::PruneDefeatedMapOrderChildrenAndReturnHead`
  (`0x5526e0`) checks its payload's strength short at `TShip+0x1c`, clears the
  ship's task-force backlink, calls the ship's virtual `Free`, and then deletes
  the link. The `TShip::Sink` caller (`0x5509c0`) reaches the same chain.

Both the map-order and mission chains therefore use a `TShip*` payload. The
link's ABI remains 16 bytes: payload `+0x00`, next `+0x04`, previous `+0x08`,
and active byte `+0x0c`. Changing its source type from `TObject*` changes no
pointer representation or field offset because `TShip`'s `TObject` base starts
at offset zero.

## Link and task-force lifecycle

`DeleteMapOrderChildLinkAndReturnNext` (`0x552590`) updates the neighboring
pointers, deletes only the link, and returns its old next link. The recursive
remove operation (`0x5525d0`) deletes the first matching link and retains the
ship. The defeated-ship prune (`0x5526e0`) is the separate path that frees the
ship before deleting the link. In `TTaskForce::Free` (`0x552930`) each ship's
backlink is cleared before its link is deleted; the global task-force queue and
mission references are released afterward.

`TTaskForce::FreeAvailables` (`0x553f10`) drops inactive links, clearing each
ship's backlink and decrementing its resource-type bucket count before unlinking.
It then folds `TShip::Finest` across the survivors into `flagship`. Five order
methods and `CommitToOrders` perform this same cleanup before their distinct
queue or map-order side effects. `OrderSailTowards` (`0x5533f0`) remains a
separate path: it calls each removed ship's `SetTaskForce(nullptr)` instead of
clearing the backlink directly, then cleans up and elects the flagship.

`TTaskForce::Remove(TShip*)` (`0x553d40`) removes the matching link, adjusts
its bucket count, reelects a removed flagship, and clears the ship's backlink.
Its out-of-line member definition expresses the actual operation without a
header body chosen for compiler expansion. `TAdmiral` asks the same
`ElectFlagship` member to update a ship's owner after reassignment.

These routines preserve the order of virtual ship callbacks, ownership changes,
link deletion, bucket updates, and selection recomputation. Some source calls
replace repeated inline machine-code bodies; instruction similarity is not the
contract for those calls.
