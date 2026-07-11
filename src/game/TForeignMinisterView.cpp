#include "game/TForeignMinisterView.h"
// SYNTHETIC: IMPERIALISM 0x004f2f20
// TForeignMinisterView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004f2fb0
// TForeignMinisterView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TForeignMinisterView, TMinisterView)

// The original inlines TMinisterView(TView(), field60(0)) directly here (only TView's
// own base ctor stays out-of-line); the recompile emits a call to TMinisterView's real
// ctor instead, which is the accepted architectural shape until ctor-inlining is
// modeled (same divergence pattern as TEscortMission(TZone*)/TNavyMission(TZone*)).
// FUNCTION: IMPERIALISM 0x004f2fd0
TForeignMinisterView::TForeignMinisterView() : TMinisterView() {}

// SYNTHETIC: IMPERIALISM 0x004f3000
// TForeignMinisterView::`scalar deleting destructor'
TForeignMinisterView::~TForeignMinisterView() {}

// FUNCTION: IMPERIALISM 0x004f3050
void TForeignMinisterView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
}

// FUNCTION: IMPERIALISM 0x004f31d0
undefined TForeignMinisterView::OrphanCallChain_C3_I22_004f31d0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004f3220
undefined TForeignMinisterView::OrphanRetStub_004f3220() {
  return 0;
}
