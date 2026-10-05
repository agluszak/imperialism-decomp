#pragma once

#include "compat.h"
#include "game/app/TObject.h"
#include "game/mfc.h"

class TView;

// VTABLE: IMPERIALISM 0x0065e230
class TLineData : public TObject {
public:
  DECLARE_DYNCREATE(TLineData)
  // FUNCTION: IMPERIALISM 0x0056f400
  virtual ~TLineData() override {} // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout); // slot 0x0a 0x56f460
  virtual void RemoveViews();                                 // slot 0x0b 0x56f480

  short column;     // 0x04
  short row;        // 0x06
  int layoutWidth;  // 0x08
  int layoutHeight; // 0x0c

  TLineData();
  void ILineData(short rowArg, short colArg, int* bounds);
};

ASSERT_SIZE(TLineData, 0x10);
ASSERT_OFFSET(TLineData, column, 0x04);
ASSERT_OFFSET(TLineData, row, 0x06);
ASSERT_OFFSET(TLineData, layoutWidth, 0x08);
ASSERT_OFFSET(TLineData, layoutHeight, 0x0c);
