#pragma once

#include "compat.h"

#include "game/ui_core/TCluster.h"
#include "game/mfc.h"

void MakeFlagButtonDialog();

// VTABLE: IMPERIALISM 0x00664b00
class TToolBarCluster : public TCluster {
public:
  DECLARE_DYNCREATE(TToolBarCluster)
  virtual ~TToolBarCluster() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x00584ea0
  virtual void HandleCursorHoverSelectionByChildHitTestAndFallback(
      CPoint* point,
      RgnHandle hitArg) override;                  // slot 0x35 0x5851c0
  virtual void AddInfoBehaviors();                 // slot 0x73 0x5853f0
  virtual void SetReadouts(short nationId);        // slot 0x74 0x585ba0
  virtual void UpdateGrantDisplay(int grantTotal); // slot 0x75 0x585ee0

  TToolBarCluster();
};
ASSERT_SIZE(TToolBarCluster, 0x88);
