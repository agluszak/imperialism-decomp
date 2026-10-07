#pragma once

#include "decomp_types.h"

#include "game/mfc.h"
#include "game/nation_domain_types.h"
#include "game/core/CString.h"
#include "game/app/TObject.h"
#include "game/stretch.h"

struct CRuntimeClass;
struct Province;
class TStream;
class TZone;
class TTaskForce;
class TAdmiral;

IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR
// VTABLE: IMPERIALISM 0x0065c74c
class TZonePrimaryNeighborStretch : public stretch<TZone*> {
public:
  TZone** Add(TZone* zone) override; // 0x55e8e0
};

// VTABLE: IMPERIALISM 0x0065c748
class TZoneSecondaryNeighborStretch : public stretch<Province*> {
public:
  Province** Add(Province* entry) override; // 0x55e9c0
};
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR

// VTABLE: IMPERIALISM 0x0065c6d8
class TZone : public TObject {
public:
  DECLARE_DYNCREATE(TZone)
  ~TZone() override;                       // slot 0x01 vector dtor 0x562880
  void WriteTo(TStream* stream) override;  // slot 0x05 0x55eff0
  void ReadFrom(TStream* stream) override; // slot 0x06 0x55ed20
  void Free() override;                    // slot 0x07 0x55ec60
  void Vanish();                           // 0x55ecd0, Mac oracle
  virtual void NameThyself(unsigned char* usedCityFlags,
                           const char* overrideName);                     // slot 0x0a 0x55f780
  virtual void AssignZoneDisplayNameToOutputRef(CString* outputRef);      // slot 0x0b 0x55f070
  virtual void AssignZoneDisplayNameAliasToOutputRef(CString* outputRef); // slot 0x0c 0x55f090
  virtual bool IsSeaZone();                                               // slot 0x0d 0x55e820
  virtual bool IsPortZone();                                              // slot 0x0e 0x55e840
  virtual bool IsProvincial();                                            // slot 0x0f 0x55e860
  virtual bool IsFriendlyWith(NationSlot nationSlot);                     // slot 0x10 0x55e880
  virtual bool IsEnemyOf(NationSlot nationSlot);                          // slot 0x11 0x55e8a0
  virtual bool CanBeTargetOf(TTaskForce* force);                          // slot 0x12 0x55e8c0
  virtual short FindNearestActiveSeaContextTileFromOffset216();           // slot 0x13 0x55fe60
  virtual short GetActiveNationSlotTile();                                // slot 0x14 0x55fef0
  virtual short FindBestCoastalTileForContextAndCityStateByHeuristic(
      Province* contextProvince);                  // slot 0x15 0x560150
  virtual void ShowFocusIngot(unsigned char show); // slot 0x16 0x560580
  // --- vtable ends at slot 0x16 (orig 0x17..0x1b are NULL; see note above) ---

  short GetContextOrdinalOrInvalid();
  void GenerateZoneStatusCodeIfUnset(); // 0x55f5c0
  void ReconsiderFocusIngot();          // 0x5604e0
  void AddNeighbor(TZone* zone);
  void AppendUniqueSecondaryNeighbor(Province* province);
  bool HasNeighbor(TZone* zone);        // 0x55f320, Mac oracle
  bool HasNeighbor(Province* province); // 0x55f3c0, Mac oracle
  TZone* GetSafestNearbyZoneFor(short nationSlot) const;
  void LightDistanceRecursive(short level); // 0x560f80
  short GetDistanceTo(TZone* other);        // 0x5610b0
  bool IsAdjacentToCountry(short nationTag);
  int IsZoneMaskOrArrayEntryPresentForKey(short key);
  bool ContainsCityStatePointerInZoneArrayByCityIndex(short cityIndex);
  bool HasFreeShipsOfPlayer(int nation, bool skipField34Check);
  void LightUp(int remainingDepth,
               bool markAdjacentCities); // 0x560ba0
  TAdmiral* GetSeniorOfficerOf(int nation);
  void GetNavalAuthority(CString* out, short nation);
  int GetStrategicValue();

  short statusCode;                             // +0x04
  char pad06[2];                                // +0x06
  CString displayName;                          // +0x08
  int tileOrTerrainId;                          // +0x0c tile / terrain id storage
  unsigned short nationKeyMask;                 // +0x10 (key mask in nation context slices)
  short seedNationId;                           // +0x12 seed nation id arg
  short contextOrdinal;                         // +0x14 context ordinal
  char pad16[2];                                // +0x16
  TZone* prev18;                                // +0x18 older in g_pMapActionContextListHead chain
  TZone* next1c;                                // +0x1c newer link
  short activeTileIndex;                        // +0x20 active tile index
  char pad22[2];                                // +0x22
  TZonePrimaryNeighborStretch primaryNeighbors; // +0x24
  TZoneSecondaryNeighborStretch secondaryNeighbors; // +0x34
  short distanceLevel;                              // +0x44

  TZone();
  void SetMapActionContextTargetTileAndRefreshMarkers(int nationSeedId, int tileIndex);

  static int ScoreCoastalTileForContextAndCityStateAffinity(int tileIndex, TZone* contextZone,
                                                            Province* contextProvince);

  void HandleKeyDown(int key_id);

  static TZone* GetFirstPortZone();
  TZone* GetNextPortZone();
  static TZone* FindPortZoneByTile(short nTileIndex);

  unsigned int GetPatrolMask();
  unsigned int BuildNationBitmaskForActiveType3Or4OrdersIncludingNation(unsigned char nation);
  unsigned int HasDiplomaticallyRelatedNationInActiveType3Or4OrderMask(int nation);

  int CountDiplomaticallyRelatedNationsInKeyMask(int nation);

  short GetPortOwnerNation();

  void ResolvePortZoneOwnerContextAndDispatch();

  TTaskForce* AssembleTaskForce(short nation);
};

ASSERT_SIZE(TZonePrimaryNeighborStretch, 0x10);
ASSERT_SIZE(TZoneSecondaryNeighborStretch, 0x10);
ASSERT_SIZE(TZone, 0x48);

TZone* GetLastMapActionContext();                  // 0x55f0d0
TZone* FindMapActionContextByNodeId(short nodeId); // 0x55f100

void ResetMapActionContextActivityAndNationFlags(); // 0x560e20

// 0x564570 moved to TOcean::GetSeaZoneAdjacentTo — every original
// callsite loads ecx = g_pActiveMapOrderContext before the call (thiscall, this unused).
