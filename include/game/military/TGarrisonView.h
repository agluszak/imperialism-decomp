#pragma once

#include "game/navy/TMilitaryPageView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064cc70
class TGarrisonView : public TMilitaryPageView {
public:
  DECLARE_DYNCREATE(TGarrisonView)
  virtual ~TGarrisonView() override; // slot 0x01 (scalar deleting destructor)
  virtual void Close() override;     // slot 0x28 0x4a8a20

  TGarrisonView();
  void StuffValues(short tileIndex);

  // No Windows access lands in +0x88. StuffValues stores the selected map tile as a word
  // at +0x8c; Close uses it to find the corresponding army-stack list.
  unsigned char padding88[4];
  short selectedTileIndex8C;
  unsigned char padding8E[2];
};
