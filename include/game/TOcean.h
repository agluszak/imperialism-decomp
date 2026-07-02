#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/TObject.h"
#include "game/TStream.h"
#include "game/TZone.h"
#include "game/global_data_tables.h"

class TCity;
class TTaskForce;

// TOcean map-order runtime singleton (g_pActiveMapOrderContext @ 0x6a3fbc).
// Ghidra historically labeled this InputState for container-level methods.
// Polymorphic MFC object (vtable 0x0065c7c8, 7 slots); per-zone nodes use TZone vtable 0x0065c6d8.
// VTABLE: IMPERIALISM 0x0065c7c8
class TOcean : public TObject {
public:
  TOcean();
  // === BEGIN GENERATED DECLS (TOcean) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TOcean)
  virtual ~TOcean(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x5628f0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x562340
  virtual void Free() override;                    // slot 0x07 0x5621e0
                                                   // === END GENERATED DECLS (TOcean) ===
  short nationCount;                               // +0x04
  TZone* contextArray;                             // +0x08
  short field0c;                                   // +0x0c
  char pad0e[2];                                   // +0x0e
  unsigned short keyMask;                          // +0x10
  char pad12[0x26];                                // +0x12 .. +0x37
  int* slotTable;                                  // +0x38
  unsigned int slotCount;                          // +0x40
  char pad44[0x14];                                // +0x44 .. +0x57 (allocation size TBD)

  void InitializeMapActionContextsForNationCountUsingCostField(int nationCountArg);

  TZone* GetMapActionContextEntryByNationCodeOffset17(short nationCode);

  // Resolves port-zone or per-nation map-action context for a sea/coastal tile.
  TZone* GetLinkedZoneForSeaTile(short seaTileIndex);

  // 0x005634a0 — walks g_pMapActionContextListHead for TPortZone tile-id match.
  void* FindPortZoneBySelectedTile(TCity* city);

  // bd 1uj.16: final step of TTaskForce::SetMapOrderType9AndQueue /
  // PromoteMapOrderChainAndQueue (0x552f80 / 0x5533f0). Not yet recovered --
  // body is a documented placeholder; see bd 1uj.16 follow-up notes.
  void FinalizeQueuedMapOrderEntry(TTaskForce* entry); // 0x5642e0
};

void NotifyMapUberPictureTileMarker(short tileIndex);

void SetMapTileStateByteAndNotifyObserver(int tileIndex, int stateByte);
int ComputeGlobalMapActionContextNodeValueAverage(void);

// === BEGIN GENERATED (TOcean) — refreshed by `just gen-class TOcean`; do not hand-edit ===
// clang-format off
// vtable @ 0x0065c7c8 (7 slots), object size 0x18, base TObject
//   slot 0x00  byte 0x00  0x00562190  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x00562140  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x005628f0  override  WriteTo
//   slot 0x06  byte 0x18  0x00562340  override  ReadFrom
// object size 0x18 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TOcean) ===
