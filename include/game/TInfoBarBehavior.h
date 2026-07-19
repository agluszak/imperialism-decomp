#pragma once

#include "game/CString.h"
#include "game/TBehavior.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064eb10
class TInfoBarBehavior : public TBehavior {
public:
  DECLARE_DYNCREATE(TInfoBarBehavior)
  virtual ~TInfoBarBehavior() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a OrphanTiny_SetDwordEcxOffset_8_00487280 inherited unchanged (0x487280)
  // slot 0x0b OrphanLeaf_NoCall_Ins02_004872a0 inherited unchanged (0x4872a0)
  // slot 0x0c CreateTDialogBehaviorInstance inherited unchanged (0x4872c0)
  // slot 0x0d OrphanRetStub_004872e0 inherited unchanged (0x4872e0)
  virtual undefined
  InitializeInfoBarTagEntryWithOptionalDummyChild(int param_1, int* param_2); // slot 0x0e 0x4b0e20
  virtual undefined RefreshInfoBarCursorPanelRegionClip();                    // slot 0x0f 0x4b0f50
  // TBehavior's own slice ends exactly at 0x10 (ASSERT_SIZE). Real CString member (ctor
  // placement-constructs it); semantics unconfirmed -- InitializeInfoBarTagEntryWith-
  // OptionalDummyChild/RefreshInfoBarCursorPanelRegionClip aren't ported yet.
  CString field10;

  TInfoBarBehavior();

  // Original object size is 0x24 (CRuntimeClass m_nObjectSize); the source class ended at 0x14. Trailing 16 byte(s) not yet semantically recovered — declared so sizeof and the recomp's allocation size match the original.
  int field14;
  int field18;
  int field1c;
  int field20;
};
