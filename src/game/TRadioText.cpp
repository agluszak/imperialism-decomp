#include "game/TRadioText.h"

#include "game/TRadioTextCluster.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"

// SYNTHETIC: IMPERIALISM 0x0043daa0
// TRadioText::`scalar deleting destructor'
TRadioText::~TRadioText() {}
// SYNTHETIC: IMPERIALISM 0x005793f0
// TRadioText::CreateObject

// SYNTHETIC: IMPERIALISM 0x00579470
// TRadioText::GetRuntimeClass

IMPLEMENT_DYNCREATE(TRadioText, TDropShadowText)

// FUNCTION: IMPERIALISM 0x0043d990
TRadioText::TRadioText() : TDropShadowText() {}

// FUNCTION: IMPERIALISM 0x00579490
void TRadioText::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
}

// FUNCTION: IMPERIALISM 0x005794b0
void TRadioText::Draw(RECT* rectBuffer) {
  if (isSelectedOption98 != 0 || controlState64 != 0) {
    // All eleven Mac TRadioText resource instances are direct children of a
    // TRadioTextCluster; the Windows body reads that owner's two color codes.
    TRadioTextCluster* cluster = static_cast<TRadioTextCluster*>(ownerContext);
    cluster->AssertValid();

    int savedColor = g_pActiveQuickDrawSurfaceContext->blitSurface.quickDrawColor;
    short colorCode = controlState64 != 0 ? cluster->word8C : cluster->word8E;
    g_pUiRuntimeContext->SetColor(colorCode, 1);

    RECT fillRect = {0, 0, frameWidth34, frameHeight38};
    FillRectWithQuickDrawBrushAndContextOffset(&fillRect);
    SetQuickDrawColorAndSyncGlobals(savedColor);
  }
  TDropShadowText::Draw(rectBuffer);
}

// FUNCTION: IMPERIALISM 0x00579580
void TRadioText::RefreshAndNotifyOwnerSlot13C() {
  RefreshControl();
  GetWindow()->ForceRedraw();
}
