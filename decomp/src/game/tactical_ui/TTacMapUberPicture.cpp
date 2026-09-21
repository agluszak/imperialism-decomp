#include "game/tactical_ui/TTacMapUberPicture.h"
#include "game/ui_tags_common.h"

#include "game/tactical/TTacticalBattleView.h"
#include "game/ui_core/TPicture.h"

// FUNCTION: IMPERIALISM 0x0045d3b0
void TTacMapUberPicture::Scroll(MapScrollEdgeMaskStorage edgeMask) {
  if (tacticalBattleView94 != nullptr) {
    tacticalBattleView94->Scroll(edgeMask);
  }
}

// SYNTHETIC: IMPERIALISM 0x0045d3e0
// TTacMapUberPicture::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0045d410
TTacMapUberPicture::~TTacMapUberPicture() {}
// FUNCTION: IMPERIALISM 0x005ad290
void TTacMapUberPicture::SetWindPictureResourceIdAndRefresh(int resourceBase) {
  TPicture* windPicture =
      static_cast<TPicture*>(ResolveControlByTag(IMPERIALISM_FOURCC('w', 'i', 'n', 'd')));
  windPicture->AssertValid();
  windPicture->SetPictureResourceIdAndRefresh(static_cast<short>(resourceBase + 0xf00), 1);
}

// SYNTHETIC: IMPERIALISM 0x005ad2e0
// TTacMapUberPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x005ad380
// TTacMapUberPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTacMapUberPicture, TMapUberUberPicture)
// FUNCTION: IMPERIALISM 0x005ad3a0
void TTacMapUberPicture::DoPostCreate(int arg) {
  TMapUberUberPicture::DoPostCreate(arg);
  tacticalBattleView94 = static_cast<TTacticalBattleView*>(ResolveControlByTag(kControlTagDialog));
  tacticalBattleView94->AssertValid();
}

// FUNCTION: IMPERIALISM 0x005ad3f0
void TTacMapUberPicture::DoKeyEvent(TToolboxEvent* event) {
  TTacticalBattleView* battleView =
      static_cast<TTacticalBattleView*>(ResolveControlByTag(kControlTagDialog));
  battleView->AssertValid();
  battleView->DoKeyEvent(event);
}
