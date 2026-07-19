#include "game/TTradeOrderPicture.h"
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
void TTradeOrderPicture::NoOpUiLifecycleHook(int arg) {
  (void)arg;
  SetState(1, 0);
}

// FUNCTION: IMPERIALISM 0x00584520
void TTradeOrderPicture::BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3,
                                                              int arg4) {
  (void)point;
  (void)arg2;
  (void)arg3;
  (void)arg4;
}
