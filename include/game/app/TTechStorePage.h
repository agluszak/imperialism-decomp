#pragma once

#include "game/ui_screens/TPageView.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class CityDialogController;

// VTABLE: IMPERIALISM 0x00645ca8
class TTechStorePage : public TPageView {
public:
  DECLARE_DYNCREATE(TTechStorePage)
  virtual ~TTechStorePage() override; // slot 0x01 (scalar deleting destructor)
  // NOTE: TTechStorePage's vtable (0x645ca8) is a TPageView clone — only slot 0x00
  // (GetRuntimeClass, via DECLARE_DYNCREATE) and slot 0x01/0x04 (scalar deleting
  // destructor) differ; every other slot is inherited unchanged from TPageView.
  // The auto-recovery over-read past the four null terminator slots (0x80-0x83) into
  // the adjacent TScroller vtable and mislabeled TScroller's TObject/TEventHandler
  // virtuals (GetRuntimeClass/Serialize/WriteTo/ReadFrom/ShallowFree/DoEvent/...)
  // as TTechStorePage slots 0x84-0x9d. Those declarations were removed; the bodies at
  // 0x479440/0x4796xx etc. belong to TScroller, not TTechStorePage.

  void PopulateUnlockedTechnologyRows(int nationSlot); // 0x005b0f10

  TTechStorePage();
};
