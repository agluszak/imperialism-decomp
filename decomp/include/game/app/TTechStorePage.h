#pragma once

#include "compat.h"

#include "game/ui_screens/TPageView.h"
#include "game/mfc.h"

class CityDialogController;

// VTABLE: IMPERIALISM 0x00645ca8
class TTechStorePage : public TPageView {
public:
  DECLARE_DYNCREATE(TTechStorePage)
  virtual ~TTechStorePage() override;

  void StuffValues(int nationSlot);

  TTechStorePage();
};
ASSERT_SIZE(TTechStorePage, 0x84);
