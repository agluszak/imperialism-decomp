#include "game/tactical_ui/TTacMapUberPicture.h"
#include "game/ui_tags_common.h"

#include "game/tactical/TTacticalBattleView.h"
#include "game/ui_core/TPicture.h"

// FUNCTION: IMPERIALISM 0x0045d3b0
void TTacMapUberPicture::Scroll(MapScrollEdgeMaskStorage edgeMask) {
  if (tacticalBattleView != NULL) {
    tacticalBattleView->Scroll(edgeMask);
  }
}

// FUNCTION: IMPERIALISM 0x0045d410
TTacMapUberPicture::~TTacMapUberPicture() {}
// FUNCTION: IMPERIALISM 0x005ad290
void TTacMapUberPicture::SetWindPictureResourceIdAndRefresh(int resourceBase) {
  TPicture* windPicture =
      static_cast<TPicture*>(FindSubView(IMPERIALISM_FOURCC('w', 'i', 'n', 'd')));
  windPicture->AssertValid();
  windPicture->SetPictureRsrcID(static_cast<short>(resourceBase + 0xf00), 1);
}

IMPLEMENT_DYNCREATE(TTacMapUberPicture, TMapUberUberPicture)
// FUNCTION: IMPERIALISM 0x005ad3a0
void TTacMapUberPicture::DoPostCreate(int arg) {
  TMapUberUberPicture::DoPostCreate(arg);
  tacticalBattleView = static_cast<TTacticalBattleView*>(FindSubView(kControlTagDialog));
  tacticalBattleView->AssertValid();
}

// FUNCTION: IMPERIALISM 0x005ad3f0
void TTacMapUberPicture::DoKeyEvent(TToolboxEvent* event) {
  TTacticalBattleView* battleView =
      static_cast<TTacticalBattleView*>(FindSubView(kControlTagDialog));
  battleView->AssertValid();
  battleView->DoKeyEvent(event);
}
