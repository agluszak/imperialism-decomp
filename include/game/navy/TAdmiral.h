#pragma once

#include "compat.h"

#include "decomp_types.h"
#include "game/mfc.h"
#include "game/ui_screens/CString.h"
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
  // Experience points. Mac resource evidence labels admirals as "amt = exp"; every
  // reader converts this to a skill tier with experiencePoints / 100 (+1 where the
  // zero-experience tier is numbered one).
  short experiencePoints; // 0x10
  unsigned char pad12[2]; // 0x12
  TAdmiral* next;         // 0x14 (toward older entries)
  TAdmiral* prev;         // 0x18 (toward newer entries)

  TAdmiral(NationSlot nationSlotArg = -1);
  virtual ~TAdmiral() override;

  // Mac oracle: AssignToShip / ReassignThyself. AssignToShip replaces the primary
  // order link and refreshes both old and new task-force child selections.
  void AssignToShip(TShip* primaryOrderNode); // 0x552250
  // ReassignThyself rescans the global primary-order list for this admiral's nation;
  // it Free()s this admiral when no ship qualifies.
  void ReassignThyself(); // 0x551850
  // Reassigns within both a zone and this admiral's nation. Ghidra split the original
  // 0x552310..0x552404 body into three overlapping orphan functions.
  void ReassignToZone(TZone* zone); // 0x552310

  // Mac oracle: Victory. A won engagement grants experience; the total is clamped to
  // 499 so the derived skill tier (experiencePoints / 100) never exceeds four.
  void Victory(short experienceGain); // 0x551820

  // Mac oracle: IsSeniorTo. Compares experience. Guards a null receiver and a null
  // argument the way the original does: a null admiral is junior to everyone, and
  // any admiral is senior to none.
  unsigned char IsSeniorTo(const TAdmiral* other) const; // 0x551990

  // Mac oracle: EstimateStrengthRating. Sums TShip::GetBattleStrengthRating over the
  // given force's child ships. The original ignores its receiver and inlines the
  // per-ship rating (TShip lives in the same original translation unit); the second
  // argument is never read. 0x552160, __thiscall.
  int EstimateStrengthRating(const TTaskForce* force, int unusedArg) const;

  // Mac oracle: NameThyself. Regenerates displayName until it is unique in the
  // global admiral list.
  void NameThyself(); // 0x552450

  // Allocate a linked admiral and report the original UNavy.cpp nil-pointer failure
  // when allocation fails. 0x5573f0.
  static TAdmiral* CreateForTerrainType(NationSlot terrainTypeIndex);

  // Mac oracle: EstimateEnemyForces / GetFleetReport. The report intentionally
  // perturbs observed ship counts and classes according to this admiral's skill.
  short EstimateEnemyForces(short* estimatedCounts, const TZone* zone, NationSlot nation) const;
  void GetFleetReport(CString* out, TZone* zone, NationSlot nation) const;
};
ASSERT_SIZE(TAdmiral, 0x1c);

CString GetLocalizedNavalReportShipType(short category, char plural);
