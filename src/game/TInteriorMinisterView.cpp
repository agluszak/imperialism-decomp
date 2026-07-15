#include "game/TInteriorMinisterView.h"
// SYNTHETIC: IMPERIALISM 0x004f35e0
// TInteriorMinisterView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004f3670
// TInteriorMinisterView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TInteriorMinisterView, TMinisterView)

// The original inlines TMinisterView(TView(), field60(0)) directly here (same
// ctor-inlining divergence already established for TForeignMinisterView).
// FUNCTION: IMPERIALISM 0x004f3690
TInteriorMinisterView::TInteriorMinisterView() : TMinisterView() {}

// SYNTHETIC: IMPERIALISM 0x004f36c0
// TInteriorMinisterView::`scalar deleting destructor'
TInteriorMinisterView::~TInteriorMinisterView() {}

// FUNCTION: IMPERIALISM 0x004f3710
void TInteriorMinisterView::HandleEvent(int commandId, TEventHandler* sourceHandler,
                                        TEvent* event) {}
