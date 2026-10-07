#include "game/military_ui/TArmyCheckBox.h"
#include "game/ui_core/TWindow.h"

#include "game/gfx/CDib.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"

// FUNCTION: IMPERIALISM 0x004a9430
TArmyCheckBox::~TArmyCheckBox() {}

IMPLEMENT_DYNCREATE(TArmyCheckBox, TControl)

// FUNCTION: IMPERIALISM 0x004a9fe0
TArmyCheckBox::TArmyCheckBox(TView* panel, int* offsetLayout, int* sizeLayout, int unused1,
                             int unused2, TQuickDrawSurfaceContext* surfaceContext90Value,
                             int iconStripHorizontalOffsetValue)
    : TControl() {
  (void)unused1;
  (void)unused2;
  InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, sizeLayout, 4, 4, 0);
  surfaceContext = surfaceContext90Value;
  iconStripHorizontalOffset = iconStripHorizontalOffsetValue;
}

// FUNCTION: IMPERIALISM 0x004aa030
void TArmyCheckBox::CheckTheLook(unsigned char drawImmediate) {
  if (isOn == 0 && controlState == 0) {
    if (checkedFrameOffsetApplied != 0) {
      iconStripHorizontalOffset -= frameWidth;
      checkedFrameOffsetApplied = 0;
      RefreshControl();
      if (drawImmediate != 0) {
        DrawImmediate();
      }
    }
  } else if (checkedFrameOffsetApplied == 0) {
    iconStripHorizontalOffset += frameWidth;
    checkedFrameOffsetApplied = 1;
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

  if (surfaceContext != 0) {
    ResetQuickDrawStrokeState();

    RECT srcRect;
    srcRect.left = rectBuffer->left + iconStripHorizontalOffset;
    srcRect.right = rectBuffer->right + iconStripHorizontalOffset;
    srcRect.bottom = rectBuffer->bottom - 1;
    srcRect.top = rectBuffer->top;

    UpdatePaletteIndexWithDefaultFallback(0x10);
    SetQuickDrawFillColor(0);

    if (surfaceContext->blitSurface.surfaceDib != 0) {
      int height = surfaceContext->blitSurface.surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
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

    BlitRectWithOptionalTransparency(surfaceContext->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &contentRect, 0x24, 0);
    UpdatePaletteIndexWithDefaultFallback(0x13);
  }
}

// FUNCTION: IMPERIALISM 0x004aa280
void TArmyCheckBox::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == kControlCommandHiliteToggle) {
    if ((GetAsyncKeyState(0x11) & 0x8000) != 0 || isOn != 0) {
      Toggle(true);
    }
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004aa2f0
void TArmyCheckBox::DoPostCreate(int arg) {
  eventNumber = 4;
}

// FUNCTION: IMPERIALISM 0x004aa310
void TArmyCheckBox::HiliteState(unsigned char hilited, bool drawImmediate) {
  if (controlState != hilited) {
    controlState = hilited;
    CheckTheLook(drawImmediate);
  }
}

// FUNCTION: IMPERIALISM 0x004aa340
unsigned char TArmyCheckBox::IsOn() {
  return isOn;
}

// FUNCTION: IMPERIALISM 0x004aa360
void TArmyCheckBox::SetState(unsigned char on, unsigned char drawImmediate) {
  if (isOn != on) {
    isOn = on;
    CheckTheLook(drawImmediate);
  }
}

// FUNCTION: IMPERIALISM 0x004aa3a0
void TArmyCheckBox::Toggle(bool drawImmediate) {
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
