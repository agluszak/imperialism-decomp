#pragma once

#include "decomp_types.h"

#include "game/CString.h"

struct CRuntimeClass;

// Map zone / map-action context node (Mac: TZone, TPortZone, TOcean hierarchy).
// Per-nation seed contexts in TMapOrderContext use the first 0x48 bytes of this layout.
// VTABLE: IMPERIALISM 0x0065c6d8
class TZone {
public:
  // vtable 0x0065c6d8 slots 0x00..0x58
  virtual CRuntimeClass* GetRuntimeClass();
  // slot 0x04 — scalar deleting destructor @ 0x562880 (SYNTHETIC; see TZone.cpp)
  virtual void HandleTurnEventVtableSlot08(int arg1);
  virtual void AssertValidOrSlot0c();
  virtual void DumpOrSlot10(int unused = 0);
  virtual void SerializeZoneToBinaryStream(void* streamState);
  virtual void DeserializeZoneFromBinaryStream(int streamState);
  virtual void RemoveZoneFromGlobalListAndRelease();
  virtual void InvokeObjectVtableMethod24();
  virtual void* HandleTurnEventVtableSlot24CopyPayloadBuffer();
  virtual void GenerateMapActionContextDisplayNameAndHeadline(int arg1, void* arg2);
  virtual void AssignZoneDisplayNameToOutputRef(void* outputRef);
  virtual void AssignZoneDisplayNameAliasToOutputRef(void* outputRef);
  virtual bool QueryZoneCapabilityFlagA();
  virtual bool QueryPortZoneCapability();
  virtual bool QueryZoneCapabilityFlagC();
  virtual bool QueryZoneCapabilityFlagD(int unused);
  virtual bool QueryZoneCapabilityFlagE(int unused);
  virtual bool HasZoneActiveChildCount(int unused);
  virtual short FindNearestActiveSeaContextTileFromOffset216();
  virtual short MapActionVtableSlot4C();
  virtual short GetActiveNationSlotTile();
  virtual short FindBestCoastalTileForContextAndCityStateByHeuristic(int contextCityState);
  virtual void SetMapOrderUiFlag(int flag);

  short field04;                  // +0x04
  char pad06[6];                  // +0x06
  int field0c;                    // +0x0c tile / terrain id storage
  unsigned short field10;         // +0x10 (key mask in nation context slices)
  short field12;                  // +0x12 seed nation id arg
  short field14;                  // +0x14 context ordinal
  char pad16[2];                  // +0x16
  TZone* prev18;                  // +0x18 older in g_pMapActionContextListHead chain
  TZone* next1c;                  // +0x1c newer link
  short field20;                  // +0x20 active tile index
  char pad22[2];                  // +0x22
  void* field24;                  // +0x24 primary array thunk ptr
  int* portZoneEntries28;         // +0x28 — per-nation port-zone entry vector (0x004dbf00 path)
  int portZoneEntryCount2c;       // +0x2c
  int portZoneActiveEntryCount30; // +0x30
  void* field34;                  // +0x34 secondary array thunk ptr
  void* field38;                  // +0x38 slot-table pointer in HandleKeyDown paths
  int field3c;                    // +0x3c
  int field40;                    // +0x40 slot-table count in HandleKeyDown paths
  int field44;                    // +0x44
  int field48;                    // +0x48 map tile index (also used as short in some paths)
  CString displayName;            // EH member; ctor initializes via empty shared-string ref

  TZone();
  virtual ~TZone();
  void SetMapActionContextTargetTileAndRefreshMarkers(int nationSeedId, int tileIndex);

  // 0x0055ff70 — coastal-tile affinity heuristic (cdecl; used by FindBestCoastalTile).
  static int ScoreCoastalTileForContextAndCityStateAffinity(int tileIndex, TZone* contextZone,
                                                            int contextCityState);

  // 0x0055fc40 — Ghidra labeled InputState::; dispatches through TZone vtable 0x50/0x58.
  void HandleKeyDown(int key_id);

  static TZone* FindFirstPortZoneContextByNation(short nationSlot);
};

// Nation-sized map-action context embedded in TMapOrderContext::contextArray (stride 0x48).
struct TMapNationActionContext {
  char storage[0x48];
};
