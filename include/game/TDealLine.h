#pragma once

#include "game/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066e238
class TDealLine : public TLineData {
public:
  DECLARE_DYNCREATE(TDealLine)
  virtual ~TDealLine() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual void CreateLineItemView(TView* panel, int* offsetLayout) override; // slot 0x0a 0x5c0e50
  // slot 0x0b OrphanRetStub_0056f480 inherited unchanged (0x56f480)

  TDealLine();

  // Original object size is 0x18 (CRuntimeClass m_nObjectSize); the source class ended at 0x10. Trailing 8 byte(s) not yet semantically recovered — declared so sizeof and the recomp's allocation size match the original.
  int field10;
  int field14;
};
