#pragma once

#include "compat.h"

#include "decomp_types.h"
#include "game/mfc.h"
#include "game/core/CString.h"
#include "game/nation/TMinor.h"
#include "game/app/TObject.h"

class TShip;
class TTaskForce;
class TZone;

// Navy task-force secondary order node (vtable 0x0065c498, eight slots).
// VTABLE: IMPERIALISM 0x0065c498
class TAdmiral : public TObject {
public:
  DECLARE_DYNCREATE(TAdmiral) // GetRuntimeClass slot 0x00
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual void Free() override;

  NationSlot nationSlot; // (also indexes the nation's terrain descriptor; -1 = none)
  unsigned char pad06[2];
  TShip* assignedShip; // linked navy primary-order node
  CString displayName;
  short experiencePoints;
  unsigned char pad12[2];
  TAdmiral* next; // (toward older entries)
  TAdmiral* prev; // (toward newer entries)

  TAdmiral(NationSlot nationSlotArg = -1);
  virtual ~TAdmiral() override;

  void AssignToShip(TShip* primaryOrderNode);
  void ReassignThyself();
  void ReassignToZone(TZone* zone);

  void Victory(short experienceGain);

  bool IsSeniorTo(const TAdmiral* other) const;

  int EstimateStrengthRating(const TTaskForce* force, int unusedArg) const;

  void NameThyself();

  static TAdmiral* CreateForTerrainType(NationSlot terrainTypeIndex);
  static void FreeAll();

  short EstimateEnemyForces(short* estimatedCounts, const TZone* zone, NationSlot nation) const;
  void GetFleetReport(CString* out, TZone* zone, NationSlot nation) const;
};
ASSERT_SIZE(TAdmiral, 0x1c);

CString GetLocalizedNavalReportShipType(short category, bool plural);
