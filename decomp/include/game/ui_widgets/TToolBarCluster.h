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
  //
  // SetMapInteractionMode/FocusOnForce/FocusOnZone (previously
  // declared here per symbols.csv's curated class attribution) moved to TMapUberPicture:
  // their own disassembly reads/writes this+0x94/0x96/0x98/0xb0..0xbf at exactly
  // TMapUberPicture's real field offsets (invalidationFlag/activeUnitCategoryIndex/
  // orderEntryContext/categoryPages[4]), and dispatches through TMapUberPicture's own
  // vtable slots (0x58 GetWindow, 0x74/Locate on categoryPages[] entries) --
  // not a further-derived, RTTI-invisible TToolBarCluster subclass as previously
  // theorized. TWorldView.cpp's ownerContext (also retyped to TMapUberPicture*) reaches
  // the same object independently, corroborating this.

  TToolBarCluster();
};
ASSERT_SIZE(TToolBarCluster, 0x88);
