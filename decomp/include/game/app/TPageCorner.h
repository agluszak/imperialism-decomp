#pragma once

#include "compat.h"

#include "game/ui_screens/TColorKeyPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0063f1f8
class TPageCorner : public TColorKeyPicture {
public:
  DECLARE_DYNCREATE(TPageCorner)
  virtual ~TPageCorner() override;
  virtual bool HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) override;

  TPageCorner();
};
ASSERT_SIZE(TPageCorner, 0x98);
