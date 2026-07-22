#include "game/TArmyCheckBox.h"
#include "game/TWindow.h"

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
                             int iconStripHorizontalOffsetValue)
    : TControl() {
  (void)unused1;
  (void)unused2;
  InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, sizeLayout, 4, 4, 0);
  surfaceContext90 = surfaceContext90Value;
  iconStripHorizontalOffset88 = iconStripHorizontalOffsetValue;
}

// FUNCTION: IMPERIALISM 0x004aa030
void TArmyCheckBox::CheckTheLook(unsigned char drawImmediate) {
  if (isOn84 == 0 && controlState64 == 0) {
    if (checkedFrameOffsetApplied8c != 0) {
      iconStripHorizontalOffset88 -= frameWidth34;
      checkedFrameOffsetApplied8c = 0;
      RefreshControl();
      if (drawImmediate != 0) {
        DrawImmediate();
      }
    }
  } else if (checkedFrameOffsetApplied8c == 0) {
    iconStripHorizontalOffset88 += frameWidth34;
    checkedFrameOffsetApplied8c = 1;
    RefreshControl();
    if (drawImmediate != 0) {
      DrawImmediate();
    }
  }
}

// FUNCTION: IMPERIALISM 0x004aa100
void TArmyCheckBox::Draw(RECT* rectBuffer) {
  RECT contentRect;
  contentRect.left = rectBuffer->left;
  contentRect.top = rectBuffer->top;
  contentRect.right = rectBuffer->right;
  contentRect.bottom = rectBuffer->bottom;

  if (surfaceContext90 != 0) {
    ResetQuickDrawStrokeState();

    RECT srcRect;
    srcRect.left = rectBuffer->left + iconStripHorizontalOffset88;
    srcRect.right = rectBuffer->right + iconStripHorizontalOffset88;
    srcRect.bottom = rectBuffer->bottom - 1;
    srcRect.top = rectBuffer->top;

    UpdatePaletteIndexWithDefaultFallback(0x10);
    SetQuickDrawFillColor(0);

    // Both source and destination rects get flipped for a negative-height
    // (bottom-up) backing DIB -- the same idiom, applied to two different
    // surfaces (surfaceContext90's icon strip, then the active draw surface).
    if (surfaceContext90->blitSurface.surfaceDib != 0) {
      int height = surfaceContext90->blitSurface.surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
      if (height < 1) {
        height = -height;
      }
      OffsetRect(&srcRect, 0, height - srcRect.top - srcRect.bottom);
    }
    if (g_pActiveQuickDrawSurfaceContext->blitSurface.surfaceDib != 0) {
      int height = g_pActiveQuickDrawSurfaceContext->blitSurface.surfaceDib->m_pInfoHeader
                       ->bmiHeader.biHeight;
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
void TArmyCheckBox::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0x21) {
    if ((GetAsyncKeyState(0x11) & 0x8000) != 0 || isOn84 != 0) {
      Toggle(1);
    }
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004aa2f0
void TArmyCheckBox::DoPostCreate(int arg) {
  (void)arg;
  eventNumber60 = 4;
}

// FUNCTION: IMPERIALISM 0x004aa310
void TArmyCheckBox::HiliteState(unsigned char hilited, unsigned char drawImmediate) {
  if (controlState64 != hilited) {
    controlState64 = hilited;
    CheckTheLook(drawImmediate);
  }
}

// FUNCTION: IMPERIALISM 0x004aa340
unsigned char TArmyCheckBox::IsOn() {
  return isOn84;
}

// FUNCTION: IMPERIALISM 0x004aa360
void TArmyCheckBox::SetState(unsigned char on, unsigned char drawImmediate) {
  if (isOn84 != on) {
    isOn84 = on;
    CheckTheLook(drawImmediate);
  }
}

// FUNCTION: IMPERIALISM 0x004aa3a0
void TArmyCheckBox::Toggle(unsigned char drawImmediate) {
  SetState(static_cast<unsigned char>(IsOn() == 0), drawImmediate);
}

// FUNCTION: IMPERIALISM 0x004aa3e0
void TArmyCheckBox::ToggleIf(unsigned char expectedState, unsigned char drawImmediate) {
  if (IsOn() == expectedState) {
    SetState(static_cast<unsigned char>(IsOn() == 0), drawImmediate);
  }
}

// FUNCTION: IMPERIALISM 0x004aa430
void TArmyCheckBox::DrawImmediate() {
  GetWindow()->ForceRedraw();
}
