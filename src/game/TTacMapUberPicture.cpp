#include "game/TTacMapUberPicture.h"

#include "game/TTacticalBattleView.h"
#include "game/ui_tags_common.h"

// FUNCTION: IMPERIALISM 0x0045d3b0
void TTacMapUberPicture::Scroll(MapScrollEdgeMaskStorage edgeMask) {
  if (tacticalBattleView94 != nullptr) {
    tacticalBattleView94->Scroll(edgeMask);
  }
}

// SYNTHETIC: IMPERIALISM 0x0045d3e0
// TTacMapUberPicture::`scalar deleting destructor'
TTacMapUberPicture::~TTacMapUberPicture() {}
// SYNTHETIC: IMPERIALISM 0x005ad2e0
// TTacMapUberPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x005ad380
// TTacMapUberPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTacMapUberPicture, TMapUberUberPicture)

TTacMapUberPicture::TTacMapUberPicture() : tacticalBattleView94(nullptr) {}

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
