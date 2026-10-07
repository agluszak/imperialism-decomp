#pragma once

#include "compat.h"

#include "game/ui_core/TCluster.h"
#include "game/mfc.h"

void MakeFlagButtonDialog();

// VTABLE: IMPERIALISM 0x00664b00
class TToolBarCluster : public TCluster {
public:
  DECLARE_DYNCREATE(TToolBarCluster)
  virtual ~TToolBarCluster() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                                   RgnHandle hitArg) override;
  virtual void AddInfoBehaviors();
  virtual void SetReadouts(short nationId);
  virtual void UpdateGrantDisplay(int grantTotal);

  TToolBarCluster();
};
ASSERT_SIZE(TToolBarCluster, 0x88);
