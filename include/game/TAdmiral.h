#pragma once

#include "decomp_types.h"
#include "game/mfc.h"
#include "game/CString.h"
#include "game/TMinor.h"
#include "game/TObject.h"

class TShip;
class TZone;

// Navy task-force secondary order node (vtable 0x0065c498, eight slots).
// VTABLE: IMPERIALISM 0x0065c498
class TAdmiral : public TObject {
public:
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  DECLARE_DYNCREATE(TAdmiral)                      // GetRuntimeClass slot 0x00 0x551410
  virtual void WriteTo(TStream* stream) override;  // 0x14 0x551670
  virtual void ReadFrom(TStream* stream) override; // 0x18 0x551700
  virtual void Free() override;                    // 0x1c 0x5515d0

  short nationSlot;       // 0x04 (also indexes the nation's terrain descriptor; -1 = none)
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

  TAdmiral(short nationSlotArg = static_cast<short>(0xffff));
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

  // Mac oracle: NameThyself. Regenerates displayName until it is unique in the
  // global admiral list.
  void NameThyself(); // 0x552450

  // Mac oracle: EstimateEnemyForces / GetFleetReport. The report intentionally
  // perturbs observed ship counts and classes according to this admiral's skill.
  short EstimateEnemyForces(short* estimatedCounts, TZone* zone, short nation) const;
  void GetFleetReport(CString* out, TZone* zone, short nation) const;
};

CString GetLocalizedNavalReportShipType(short category, char plural);
