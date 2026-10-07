#pragma once

#include "compat.h"

#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065e480
class TPictureLine : public TLineData {
public:
  DECLARE_DYNCREATE(TPictureLine)
  // FUNCTION: IMPERIALISM 0x005700d0
  virtual ~TPictureLine() override {}
  virtual void InstallViews(TView* panel, int* offsetLayout) override;

  // NOOP: verified empty in original 0x00570032
  TPictureLine() {}

  void SetPictureLineRowBoundsAndResource(short rowArg, short colArg, int* bounds,
                                          short pictureResourceId);

  short pictureResourceId;
  short reserved12;
};
ASSERT_SIZE(TPictureLine, 0x14);
