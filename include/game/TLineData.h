#pragma once

#include "compat.h"
#include "game/TObject.h"
#include "game/mfc.h"

class TView;

// VTABLE: IMPERIALISM 0x0065e230
class TLineData : public TObject {
public:
  DECLARE_DYNCREATE(TLineData)
  virtual ~TLineData() override; // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout); // slot 0x0a 0x56f460
  virtual void RemoveViews();                                 // slot 0x0b 0x56f480

  short field04; // 0x04
  short field06; // 0x06
  int field08;   // 0x08
  int field0c;   // 0x0c

  TLineData();
  // 0x56f420 — set the row/col shorts and the two bound dwords from a caller pair array.
  void SetLineDataRowAndBounds(short rowArg, short colArg, int* bounds);
};

ASSERT_SIZE(TLineData, 0x10);
