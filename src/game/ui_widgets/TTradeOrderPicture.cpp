#include "game/ui_widgets/TTradeOrderPicture.h"

#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_widgets/TTradeCluster.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
// SYNTHETIC: IMPERIALISM 0x005843e0
// TTradeOrderPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x00584460
// TTradeOrderPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTradeOrderPicture, TPicture)

// FUNCTION: IMPERIALISM 0x00584480
TTradeOrderPicture::TTradeOrderPicture() {}

// SYNTHETIC: IMPERIALISM 0x005844b0
// TTradeOrderPicture::`scalar deleting destructor'
TTradeOrderPicture::~TTradeOrderPicture() {}

// FUNCTION: IMPERIALISM 0x00584500
void TTradeOrderPicture::DoPostCreate(int arg) {
  (void)arg;
  SetState(1, 0);
}

// FUNCTION: IMPERIALISM 0x00584520
void TTradeOrderPicture::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {
  (void)point;
  (void)event;
  (void)origin;

  if (IsActionable() == 0) {
    return;
  }

  TTradeCluster* tradeRow = static_cast<TTradeCluster*>(ownerContext);
  if (controlTag == 0x63617264) { // 'card'
    if (glyphBase84 == 0x83f || glyphBase84 == 0x84d) {
      g_pSfxPlaybackSystem->PlaySoundEffect(0x4269, 0, 1);
      tradeRow->HandleEvent(0x67, this, 0);
      tradeRow->DoControlAction();
      return;
    }
    g_pSfxPlaybackSystem->PlaySoundEffect(0x4269, 0, 1);
    tradeRow->HandleEvent(0x68, this, 0);
    tradeRow->SetTradeBidControlBitmap();
    tradeRow->SetTradeOfferSecondaryBitmap();
    tradeRow->HandleEvent(0x6a, this, 0);
    return;
  }

  if (controlTag == 0x6f666672) { // 'offr'
    if (glyphBase84 == 0x841 || glyphBase84 == 0x84f) {
      g_pSfxPlaybackSystem->PlaySoundEffect(0x4269, 0, 1);
      tradeRow->HandleEvent(0x6a, this, 0);
      tradeRow->SetTradeOfferSecondaryBitmap();
      return;
    }
    g_pSfxPlaybackSystem->PlaySoundEffect(0x4269, 0, 1);
    tradeRow->HandleEvent(0x69, this, 0);
    tradeRow->SetTradeOfferControlBitmap();
    if (tradeRow->IsSelectionAllowed() != 0) {
      tradeRow->DoControlAction();
      tradeRow->HandleEvent(0x67, this, 0);
    }
  }
}
