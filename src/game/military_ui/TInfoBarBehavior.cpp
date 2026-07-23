#include "game/military_ui/TInfoBarBehavior.h"
#include "game/ui_tags_military.h"

#include "game/ui_widgets/TInfoBarText.h"
#include "game/ui_core/TView.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
// SYNTHETIC: IMPERIALISM 0x004b0c90
// TInfoBarBehavior::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b0d10
// TInfoBarBehavior::GetRuntimeClass

IMPLEMENT_DYNCREATE(TInfoBarBehavior, TBehavior)

// FUNCTION: IMPERIALISM 0x004b0d30
TInfoBarBehavior::TInfoBarBehavior() : TBehavior() {}

// SYNTHETIC: IMPERIALISM 0x004b0da0
// TInfoBarBehavior::`scalar deleting destructor'
TInfoBarBehavior::~TInfoBarBehavior() {}

// FUNCTION: IMPERIALISM 0x004b0e20
void TInfoBarBehavior::IInfoBarBehavior(CString newText, TView* ownerView) {
  behaviorTag = kControlTagInfB;
  ownerView->QueryBounds(&layoutRect);
  text = newText;

  if (ownerView->EvaluateControlInputGate() == 0) {
    TView* dummy = new TView();
    dummy->InitializeUiResourceEntryFrameAndParent(0, ownerView, g_InfoBarDummyOrigin_006A2410,
                                                   &ownerView->frameWidth34, 0, 0, 0);
    dummy->controlTag = kControlTagDumy;
    dummy->SetState(1, 0);
    dummy->SetEnabled(0, 0);
  }
  ownerView->AddBehavior(this);
}

// FUNCTION: IMPERIALISM 0x004b0f50
unsigned char TInfoBarBehavior::DoSetCursor(CPoint* point, RgnHandle region) {
  (void)point;
  if (g_pCursorControlPanel != 0) {
    g_pCursorControlPanel->SetTextAndLayoutRect(text, &layoutRect);
    static_cast<TView*>(owner)->PrepareForDrawing();
    if (EmptyRgn(region) != 0) {
      SetRectRgn(region, 0, 0, 0x280, 0x1e0);
    }
  }
  return 0;
}
