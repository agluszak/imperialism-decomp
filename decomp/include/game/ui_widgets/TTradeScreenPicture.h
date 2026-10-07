#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066dd98
class TTradeScreenPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TTradeScreenPicture)
  virtual ~TTradeScreenPicture() override;
  virtual void Draw(RECT* rectBuffer) override;

  TTradeScreenPicture();
};
ASSERT_SIZE(TTradeScreenPicture, 0x90);

#ifdef IMPERIALISM_RUNTIME_TESTS
int RuntimeTradeDynamicDrawCount();
int RuntimeTradeTransparentTextDrawCount();
#endif
