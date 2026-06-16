# TGreatPower vtable contract

This document captures the frozen lifecycle-prefix contract for `TGreatPower`
after the TObject inheritance migration.

## Class anchors

- Class: `TGreatPower : public TObject`
- Vtable: `0x00653938`
- Runtime class body: `0x004d89d0` (`GetRuntimeClass`)
- Scalar deleting destructor: `0x004d8c20` (`// SYNTHETIC`)
- Real destructor body: `0x004d8c50`

## Prefix slots

| vtable+0x | Slot | Owner | Body / note |
|---|---:|---|---|
| `0x00` | 0 | `TGreatPower::GetRuntimeClass` | `0x004d89d0` |
| `0x04` | 1 | scalar deleting dtor | `0x004d8c20` (`// SYNTHETIC`) |
| `0x08` | 2 | `TObject`/`CObject` prefix | inherited `Serialize` |
| `0x0c` | 3 | `TObject`/`CObject` prefix | inherited `AssertValid` |
| `0x10` | 4 | `TObject`/`CObject` prefix | inherited `Dump` |
| `0x14` | 5 | `TGreatPower::WriteTo` | `0x004d9c70` |
| `0x18` | 6 | `TGreatPower::ReadFrom` | `0x004d92e0` |
| `0x1c` | 7 | `TGreatPower::Free` | `0x004d9160` |
| `0x20` | 8 | `TObject` prefix | inherited `ShallowClone` |
| `0x24` | 9 | `TObject` prefix | inherited `ShallowFree` |

## Scope freeze

- `vtable+0x28` and later entries are game-domain virtuals tracked in
  `docs/tgreatpower_vtable_evidence.csv`.
- `TAutoGreatPower` may override game-domain slots, but the lifecycle prefix
  above must remain stable.
