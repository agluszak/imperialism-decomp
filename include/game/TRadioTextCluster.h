#pragma once

#include "game/TCluster.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00662418
class TRadioTextCluster : public TCluster {
public:
  DECLARE_DYNCREATE(TRadioTextCluster)
  virtual ~TRadioTextCluster() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x00579770
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x579740
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x579a60

  TRadioTextCluster();

  // Mac CodeWarrior oracle: AddItem(unsigned long, int, const char*, int, int).
  // Creates, attaches, captions, and enables one TRadioText child. 0x005798a0.
  class TRadioText* AddItem(unsigned long tag, int value, const char* text, int height, int bottom);

  // Non-virtual: 0x5797c0. Shared "selectable text option" primitive used directly (not
  // through the vtable) by several dialog builders (country/protocol/difficulty pickers)
  // that construct a TRadioTextCluster of TRadioText children. Syncs selectedTag88 to
  // `tag`, then walks childList44 marking the TRadioText child whose controlTag matches
  // as selected (isSelectedOption98) and clearing the others, refreshing each that
  // changed (unless tag == 0).
  void SetSelectedTextOptionByTag(int tag, bool refreshOnChange);

  int selectedTag88;           // 0x88 — DoPostCreate seeds 'nada'
  short word8C;                // 0x8c — ctor 0x5796a0 seeds 0x4b
  short word8E;                // 0x8e — ctor seeds 0x49
  short frameThemeCode90;      // 0x90 — Draw maps this theme and frames the cluster
  short itemInset92;           // 0x92 — left/right inset for AddItem, ctor seeds 0
  short itemVerticalSpacing94; // 0x94 — next-item spacing for AddItem, ctor seeds 2
  short pad96;                 // 0x96
};
ASSERT_SIZE(TRadioTextCluster, 0x98);
