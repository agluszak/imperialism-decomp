#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

class TView;

// VTABLE: IMPERIALISM 0x0065e230
class TLineData : public TObject {
public:
  // === BEGIN GENERATED DECLS (TLineData) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TLineData)
  virtual ~TLineData() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual void CreateLineItemView(TView* panel, int* offsetLayout); // slot 0x0a 0x56f460
  virtual undefined OrphanRetStub_0056f480();                       // slot 0x0b 0x56f480
  // === END GENERATED DECLS (TLineData) ===

  short field04; // 0x04
  short field06; // 0x06
  int field08;   // 0x08
  int field0c;   // 0x0c

  TLineData();
  // 0x56f420 — set the row/col shorts and the two bound dwords from a caller pair array.
  void SetLineDataRowAndBounds(short rowArg, short colArg, int* bounds);
};
