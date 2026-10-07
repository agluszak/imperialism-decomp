#pragma once

#include "game/ui_core/TCluster.h"
#include "game/ui_tags_common.h"
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

  class TRadioText* AddItem(unsigned long tag, int value, const char* text, int height, int bottom);

  void SetSelectedTextOptionByTag(int tag, bool refreshOnChange);

  int selectedTag;           // 0x88 — DoPostCreate seeds 'nada'
  short selectedColorCode;   // 0x8c — ctor 0x5796a0 seeds 0x4b
  short unselectedColorCode; // 0x8e — ctor seeds 0x49
  short frameThemeCode;      // 0x90 — Draw maps this theme and frames the cluster
  short itemInset;           // 0x92 — left/right inset for AddItem, ctor seeds 0
  short itemVerticalSpacing; // 0x94 — next-item spacing for AddItem, ctor seeds 2
  short pad96;               // 0x96
};
ASSERT_SIZE(TRadioTextCluster, 0x98);
