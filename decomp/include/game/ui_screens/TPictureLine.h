#pragma once

#include "compat.h"

#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065e480
class TPictureLine : public TLineData {
public:
  DECLARE_DYNCREATE(TPictureLine)
  // FUNCTION: IMPERIALISM 0x005700d0
  virtual ~TPictureLine() override {} // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x570130

  // NOOP: verified empty in original 0x00570032
  TPictureLine() {}

  void SetPictureLineRowBoundsAndResource(short rowArg, short colArg, int* bounds,
                                          short pictureResourceId); // 0x5700f0

  short pictureResourceId;
  short reserved12;
};
ASSERT_SIZE(TPictureLine, 0x14);
