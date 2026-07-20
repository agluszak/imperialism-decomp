#include "game/TArmyCheckBox.h"

#include "game/CDib.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"

// SYNTHETIC: IMPERIALISM 0x004a9400
// TArmyCheckBox::`scalar deleting destructor'
TArmyCheckBox::~TArmyCheckBox() {}
// SYNTHETIC: IMPERIALISM 0x004a9f20
// TArmyCheckBox::CreateObject

// SYNTHETIC: IMPERIALISM 0x004a9fc0
// TArmyCheckBox::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyCheckBox, TControl)

TArmyCheckBox::TArmyCheckBox() {}

// FUNCTION: IMPERIALISM 0x004a9fe0
TArmyCheckBox::TArmyCheckBox(TView* panel, int* offsetLayout, int* sizeLayout, int unused1,
                             int unused2, TQuickDrawSurfaceContext* surfaceContext90Value,
                             int field88Value)
    : TControl() {
  (void)unused1;
  (void)unused2;
  InitializeUiResourceEntryFrameAndParent(nullptr, panel, offsetLayout, sizeLayout, 4, 4, 0);
  surfaceContext90 = surfaceContext90Value;
  field88 = field88Value;
}

// FUNCTION: IMPERIALISM 0x004aa030
undefined TArmyCheckBox::VTableSlot73(char param_1) {
  (void)param_1;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004aa100
void TArmyCheckBox::ApplyRectSlot110(RECT* rectBuffer) {
  RECT contentRect;
  contentRect.left = rectBuffer->left;
  contentRect.top = rectBuffer->top;
  contentRect.right = rectBuffer->right;
  contentRect.bottom = rectBuffer->bottom;

  if (surfaceContext90 != 0) {
    ResetQuickDrawStrokeState();

    RECT srcRect;
    srcRect.left = rectBuffer->left + field88;
    srcRect.right = rectBuffer->right + field88;
    srcRect.bottom = rectBuffer->bottom - 1;
    srcRect.top = rectBuffer->top;

    UpdatePaletteIndexWithDefaultFallback(0x10);
    SetQuickDrawFillColor(0);

    // Both source and destination rects get flipped for a negative-height
    // (bottom-up) backing DIB -- the same idiom, applied to two different
    // surfaces (surfaceContext90's icon strip, then the active draw surface).
    if (surfaceContext90->surfaceDib != 0) {
      int height = surfaceContext90->surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
      if (height < 1) {
        height = -height;
      }
      OffsetRect(&srcRect, 0, height - srcRect.top - srcRect.bottom);
    }
    if (g_pActiveQuickDrawSurfaceContext->surfaceDib != 0) {
      int height = g_pActiveQuickDrawSurfaceContext->surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
      if (height < 1) {
        height = -height;
      }
      OffsetRect(&contentRect, 0, height - contentRect.top - contentRect.bottom);
    }

    BlitRectWithOptionalTransparency(surfaceContext90->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &contentRect, 0x24, 0);
    UpdatePaletteIndexWithDefaultFallback(0x13);
  }
}

// FUNCTION: IMPERIALISM 0x004aa280
void TArmyCheckBox::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0x21) {
    if ((GetAsyncKeyState(0x11) & 0x8000) != 0 || field84 != 0) {
      OrphanCallChain_C2_I16_004aa3a0(1);
    }
  }
  TControl::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004aa2f0
void TArmyCheckBox::NoOpUiLifecycleHook(int arg) {
  (void)arg;
  frameStyle60 = 4;
}

// FUNCTION: IMPERIALISM 0x004aa310
void TArmyCheckBox::SetControlStateFlagAndMaybeRefresh(bool fEnabledState, bool fRefreshNow) {}

// FUNCTION: IMPERIALISM 0x004aa340
undefined TArmyCheckBox::OrphanLeaf_NoCall_Ins02_004aa340() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004aa360
undefined TArmyCheckBox::SetArmyUnitLineActiveFlagAndNotify() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004aa3a0
undefined TArmyCheckBox::OrphanCallChain_C2_I16_004aa3a0(int unused) {
  (void)unused;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004aa3e0
undefined TArmyCheckBox::OrphanCallChain_C3_I23_004aa3e0(char param_1, undefined4 param_2) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004aa430
undefined TArmyCheckBox::OrphanCallChain_C1_I05_004aa430() {
  return 0;
}
