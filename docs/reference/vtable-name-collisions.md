# Vtable name collisions

Status: resolved in source. The shape-only class batch skipped these classes
because the vtable address was already carried by a `// VTABLE:` annotation on a
different source class. The manifest class name remains authoritative; it comes
from the binary RTTI / `CRuntimeClass` chain, not from earlier placeholder names.

## Resolved mappings

Scenario A rows were pure source renames. The existing hand-recovered layout and
method bodies moved to the manifest name.

| Manifest name | Previous source name |
|---|---|
| `TApplication` | `ApplicationUiRootController` |
| `TCivUnit` | `TCivWorkOrderState` |
| `TDiplomacyMgr` | `TDiplomacyTurnStateManager` |
| `TSimMgr` | `TLocalizationRuntime` |
| `TTechMgr` | `TCityOrderCapabilityState` |
| `TTown` | `TTownMarker` |
| `TUnit` | `TUnitOrderState` |

Scenario B rows were distinct placeholder classes with the wrong vtable
annotation. Their `// VTABLE:` addresses now match their own manifests, which
removes the address collision and lets a later focused `gen-class` / porting pass
recover the manifest class without stealing existing body ownership.

| Manifest class unblocked | Vtable | Placeholder kept | Placeholder vtable |
|---|---:|---|---:|
| `TCtlMgr` | `0x0064a2b8` | `TButton` | `0x0064a4e0` |
| `TNextDiplomationCommand` | `0x00654e50` | `TNextTradeCommand` | `0x0066da90` |
| `TOverlayRadioButton` | `0x00643a40` | `TRadioPictureButton` | `0x0065f670` |
| `TShipOrder` | `0x0064f738` | `TCapacityOrder` | `0x0064f678` |
| `TTradeMgr` | `0x0066d990` | `TDealList` | `0x0066da38` |

## Follow-up rule

For the Scenario B manifest classes, generate or port bodies only in a focused
class-recovery pass. A shape-only `gen-class --no-bodies` scaffold compiles, but
it adds recomp-only methods and stats noise unless it is paired with real method
promotion. The collision fix itself is the placeholder annotation split above.
