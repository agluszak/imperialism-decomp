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
  TZone** Add(TZone* zone) override;
};

// VTABLE: IMPERIALISM 0x0065c748
class TZoneSecondaryNeighborStretch : public stretch<Province*> {
public:
  Province** Add(Province* entry) override;
};
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR

// VTABLE: IMPERIALISM 0x0065c6d8
class TZone : public TObject {
public:
  DECLARE_DYNCREATE(TZone)
  ~TZone() override; // slot 0x01 vector dtor
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void Free() override;
  void Vanish();
  virtual void NameThyself(unsigned char* usedCityFlags, const char* overrideName);
  virtual void AssignZoneDisplayNameToOutputRef(CString* outputRef);
  virtual void AssignZoneDisplayNameAliasToOutputRef(CString* outputRef);
  virtual bool IsSeaZone();
  virtual bool IsPortZone();
  virtual bool IsProvincial();
  virtual bool IsFriendlyWith(NationSlot nationSlot);
  virtual bool IsEnemyOf(NationSlot nationSlot);
  virtual bool CanBeTargetOf(TTaskForce* force);
  virtual short PickPennantIngotTile();
  virtual short PickIngotTile();
  virtual short PickInvasionIngotTile(Province* contextProvince);
  virtual void ShowFocusIngot(unsigned char flag);

  short GetContextOrdinalOrInvalid();
  void GenerateZoneStatusCodeIfUnset();
  void ReconsiderFocusIngot();
  void AddNeighbor(TZone* zone);
  void AppendUniqueSecondaryNeighbor(Province* province);
  bool HasNeighbor(TZone* zone);
  bool HasNeighbor(Province* province);
  TZone* GetSafestNearbyZoneFor(short nationSlot) const;
  void LightDistanceRecursive(short level);
  short GetDistanceTo(TZone* other);
  bool IsAdjacentToCountry(short nationTag);
  int IsVisibleToCountry(short key);
  bool ContainsProvince(short cityIndex);
  bool HasFreeShipsOfPlayer(int nation, bool skipField34Check);
  void LightUp(int remainingDepth, bool markAdjacentCities);
  TAdmiral* GetSeniorOfficerOf(int nation);
  void GetNavalAuthority(CString* out, short nation);
  int GetStrategicValue();

  short statusCode;
  char pad06[2];
  CString displayName;
  int tileOrTerrainId;          // tile / terrain id storage
  unsigned short nationKeyMask; // (key mask in nation context slices)
  short seedNationId;           // seed nation id arg
  short contextOrdinal;         // context ordinal
  char pad16[2];
  TZone* prev18;         // older in g_pMapActionContextListHead chain
  TZone* next1c;         // newer link
  short activeTileIndex; // active tile index
  char pad22[2];
  TZonePrimaryNeighborStretch primaryNeighbors;
  TZoneSecondaryNeighborStretch secondaryNeighbors;
  short distanceLevel;

  TZone();
  void SetIngotTile(short nationSeedId, int tileIndex);

  static int ScoreCoastalTile(short tileIndex, TZone* contextZone, Province* contextProvince);

  void OccupyBy(int nation);

  static TZone* GetFirstPort();
  TZone* GetNextPort();
  static TZone* FindPortZoneByTile(short nTileIndex);

  unsigned int GetPatrolMask();
  unsigned int GetPatrolMaskWith(unsigned char nation);
  unsigned int HasEnemyPatrol(int nation);

  int CountEnemiesPresent(int nation);

  short GetPortOwnerNation();

  void ResolvePortZoneOwnerContextAndDispatch();

  TTaskForce* AssembleTaskForce(short nation);
};

ASSERT_SIZE(TZonePrimaryNeighborStretch, 0x10);
ASSERT_SIZE(TZoneSecondaryNeighborStretch, 0x10);
ASSERT_SIZE(TZone, 0x48);

TZone* GetLastMapActionContext();
TZone* FindMapActionContextByNodeId(short nodeId);

void ResetZoneActivity();
