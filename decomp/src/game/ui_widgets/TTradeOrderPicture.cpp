#include "game/ui_widgets/TTradeOrderPicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"

#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_widgets/TTradeCluster.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

IMPLEMENT_DYNCREATE(TTradeOrderPicture, TPicture)

// FUNCTION: IMPERIALISM 0x00584480
TTradeOrderPicture::TTradeOrderPicture() {}

// FUNCTION: IMPERIALISM 0x005844e0
TTradeOrderPicture::~TTradeOrderPicture() {}

// FUNCTION: IMPERIALISM 0x00584500
void TTradeOrderPicture::DoPostCreate(int arg) {
  ViewEnable(1, 0);
}

// FUNCTION: IMPERIALISM 0x00584520
void TTradeOrderPicture::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {

  if (!IsActionable()) {
    return;
  }

  TTradeCluster* tradeRow = static_cast<TTradeCluster*>(ownerContext);
  if (controlTag == kControlTagCard) { // 'card'
    if (glyphBase == 0x83f || glyphBase == 0x84d) {
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

  if (controlTag == kControlTagOffr) { // 'offr'
    if (glyphBase == 0x841 || glyphBase == 0x84f) {
      g_pSfxPlaybackSystem->PlaySoundEffect(0x4269, 0, 1);
      tradeRow->HandleEvent(0x6a, this, 0);
      tradeRow->SetTradeOfferSecondaryBitmap();
      return;
    }
    g_pSfxPlaybackSystem->PlaySoundEffect(0x4269, 0, 1);
    tradeRow->HandleEvent(0x69, this, 0);
    tradeRow->SetTradeOfferControlBitmap();
    if (tradeRow->IsSelectionAllowed()) {
      tradeRow->DoControlAction();
      tradeRow->HandleEvent(0x67, this, 0);
    }
  }
}

#ifdef IMPERIALISM_RUNTIME_TESTS
void TTradeOrderPicture::ActivateOrderSemantically() {
  TTradeCluster* tradeRow = static_cast<TTradeCluster*>(ownerContext);
  if (controlTag == kControlTagCard) {
    if (glyphBase == 0x83f || glyphBase == 0x84d) {
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

  if (controlTag == kControlTagOffr) {
    if (glyphBase == 0x841 || glyphBase == 0x84f) {
      g_pSfxPlaybackSystem->PlaySoundEffect(0x4269, 0, 1);
      tradeRow->HandleEvent(0x6a, this, 0);
      tradeRow->SetTradeOfferSecondaryBitmap();
      return;
    }
    g_pSfxPlaybackSystem->PlaySoundEffect(0x4269, 0, 1);
    tradeRow->HandleEvent(0x69, this, 0);
    tradeRow->SetTradeOfferControlBitmap();
    if (tradeRow->IsSelectionAllowed()) {
      tradeRow->DoControlAction();
      tradeRow->HandleEvent(0x67, this, 0);
    }
  }
}
#endif
