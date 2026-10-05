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
  DECLARE_DYNCREATE(TAdmiral)                      // GetRuntimeClass slot 0x00 0x551410
  virtual void WriteTo(TStream* stream) override;  // 0x14 0x551670
  virtual void ReadFrom(TStream* stream) override; // 0x18 0x551700
  virtual void Free() override;                    // 0x1c 0x5515d0

  NationSlot nationSlot;  // 0x04 (also indexes the nation's terrain descriptor; -1 = none)
  unsigned char pad06[2]; // 0x06
  TShip* assignedShip;    // 0x08 — linked navy primary-order node (0x00552250)
  CString displayName;    // 0x0c
  short experiencePoints; // 0x10
  unsigned char pad12[2]; // 0x12
  TAdmiral* next;         // 0x14 (toward older entries)
  TAdmiral* prev;         // 0x18 (toward newer entries)

  TAdmiral(NationSlot nationSlotArg = -1);
  virtual ~TAdmiral() override;

  void AssignToShip(TShip* primaryOrderNode); // 0x552250
  void ReassignThyself(); // 0x551850
  void ReassignToZone(TZone* zone); // 0x552310

  void Victory(short experienceGain); // 0x551820

  unsigned char IsSeniorTo(const TAdmiral* other) const; // 0x551990

  int EstimateStrengthRating(const TTaskForce* force, int unusedArg) const;

  void NameThyself(); // 0x552450

  static TAdmiral* CreateForTerrainType(NationSlot terrainTypeIndex);
  static void FreeAll(); // 0x551640, Mac oracle

  short EstimateEnemyForces(short* estimatedCounts, const TZone* zone, NationSlot nation) const;
  void GetFleetReport(CString* out, TZone* zone, NationSlot nation) const;
};
ASSERT_SIZE(TAdmiral, 0x1c);

CString GetLocalizedNavalReportShipType(short category, bool plural);
