# TDiplomacyMapView Layout Evidence

This document records the structural layout and member field offsets for `TDiplomacyMapView` reconstructed from disassembly matching and slice discovery.

## Discovered Offsets

| Offset (Hex) | Type | Name | Purpose / Notes |
|---|---|---|---|
| `0x00` | `void*` | `vftable` | Primary Virtual Function Table (`0x00655b68`) |
| `0x98` | `short` | `frameRegionSelectorAt98` | Active nation/region index selector for legend display |
| `0x524` | `int` | `legendSurfaceModeAt524` | Legend rendering mode surface dirty/mode flag (0 = unset, 1 = mode 1, 4 = mode 4) |
| `0x1eac` | `DiplomacyMaskBufferRun[23]` | `maskBuffers` | Array of 23 monochrome mask buffer structures (each `0x14` bytes) |
| `0x2078` | `char[23][0x30]` | `packedColorBuffers` | Array of 23 packed color buffers (each `0x30` bytes) used in palette blits |

## Struct Details

### `DiplomacyMaskBufferRun` (Size: `0x14` bytes)
* `0x00`: `unsigned char* maskBytes`
* `0x04`: `int left`
* `0x08`: `int top`
* `0x0c`: `int right`
* `0x10`: `int bottom`
