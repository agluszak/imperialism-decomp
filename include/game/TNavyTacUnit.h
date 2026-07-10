#pragma once

#include "game/TTacticalUnit.h"
#include "game/mfc.h"

// TODO(manifest): describe TNavyTacUnit and its role. Base edge (TTacticalUnit) recovered from RTTI CRuntimeClass chain: TNavyTacUnit -> TTacticalUnit -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x00669708
class TNavyTacUnit : public TTacticalUnit {
public:
  // === BEGIN GENERATED DECLS (TNavyTacUnit) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TNavyTacUnit)
  virtual ~TNavyTacUnit() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual int GetBaseActionPoints() override;                    // slot 0x0a 0x5a6310
  virtual int GetUnitRange() override;                           // slot 0x0b 0x5a6330
  virtual undefined OrphanLeaf_NoCall_Ins02_005a5d80() override; // slot 0x0c 0x5a6350
  virtual undefined OrphanLeaf_NoCall_Ins02_005a5da0() override; // slot 0x0d 0x5a6370
  // slot 0x0e ApplyTacticalDamage inherited unchanged (0x5a5e70)
  // slot 0x0f FlipUnitSideAffiliation inherited unchanged (0x5a5eb0)
  virtual undefined ConstructTNavyPlayerBaseState(); // slot 0x10 0x59ed60
                                                     // === END GENERATED DECLS (TNavyTacUnit) ===

  // Navy slice (+0x34..): mostly unrecovered; +0x3c is the per-ship action-point
  // store read back by GetBaseActionPoints (0x5a6310).
  class TTaskForce* sourceTaskForce34; // +0x34 source fleet (range delegate, 0x5a6330)
  unsigned char pad38[4];              // +0x38
  int baseActionPoints3c;              // +0x3c

  TNavyTacUnit();
};
