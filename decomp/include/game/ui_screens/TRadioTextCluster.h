#pragma once

#include "game/ui_core/TCluster.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00662418
class TRadioTextCluster : public TCluster {
public:
  DECLARE_DYNCREATE(TRadioTextCluster)
  virtual ~TRadioTextCluster() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;

  TRadioTextCluster();

  class TRadioText* AddItem(unsigned long tag, int value, const char* text, int height, int bottom);

  void SetSelectedTextOptionByTag(int tag, bool refreshOnChange);

  int selectedTag;           // DoPostCreate seeds 'nada'
  short selectedColorCode;   // ctor 0x5796a0 seeds 0x4b
  short unselectedColorCode; // ctor seeds 0x49
  short frameThemeCode;      // Draw maps this theme and frames the cluster
  short itemInset;           // left/right inset for AddItem, ctor seeds 0
  short itemVerticalSpacing; // next-item spacing for AddItem, ctor seeds 2
  short pad96;
};
ASSERT_SIZE(TRadioTextCluster, 0x98);
