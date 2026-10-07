#include "game/military_ui/TInfoBarBehavior.h"
#include "game/ui_tags_military.h"

#include "game/ui_widgets/TInfoBarText.h"
#include "game/ui_core/TView.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

IMPLEMENT_DYNCREATE(TInfoBarBehavior, TBehavior)

// FUNCTION: IMPERIALISM 0x004b0d30
TInfoBarBehavior::TInfoBarBehavior() : TBehavior() {}

// FUNCTION: IMPERIALISM 0x004b0dd0
TInfoBarBehavior::~TInfoBarBehavior() {}

// FUNCTION: IMPERIALISM 0x004b0e20
void TInfoBarBehavior::IInfoBarBehavior(CString newText, TView* ownerView) {
  behaviorTag = kControlTagInfB;
  ownerView->QueryBounds(&layoutRect);
  text = newText;

  if (!ownerView->EvaluateControlInputGate()) {
    TView* dummy = new TView();
    dummy->InitializeUiResourceEntryFrameAndParent(0, ownerView, g_InfoBarDummyOrigin,
                                                   &ownerView->frameWidth, 0, 0, 0);
    dummy->controlTag = kControlTagDumy;
    dummy->ViewEnable(1, 0);
    dummy->Show(0, 0);
  }
  ownerView->AddBehavior(this);
}

// FUNCTION: IMPERIALISM 0x004b0f50
bool TInfoBarBehavior::DoSetCursor(CPoint* point, RgnHandle region) {
  if (g_pCursorControlPanel != 0) {
    g_pCursorControlPanel->SetTextAndLayoutRect(text, &layoutRect);
    static_cast<TView*>(owner)->PrepareForDrawing();
    if (EmptyRgn(region) != 0) {
      SetRectRgn(region, 0, 0, 0x280, 0x1e0);
    }
  }
  return false;
}
