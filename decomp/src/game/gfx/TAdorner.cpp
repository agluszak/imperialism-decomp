#include "game/gfx/TAdorner.h"

#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"

IMPLEMENT_DYNCREATE(TAdorner, TObject)

static void PulseUiInvalidationFlag() {
  int previous = SetGlobalUiInvalidationFlagAndReturnPrevious(0);
  SetGlobalUiInvalidationFlagAndReturnPrevious(previous);
}

// FUNCTION: IMPERIALISM 0x0049d900
void TAdorner::AddedToView(TView*) {
  PulseUiInvalidationFlag();
}

// FUNCTION: IMPERIALISM 0x0049d930
void TAdorner::RemovedFromView(TView*) {
  PulseUiInvalidationFlag();
}

// FUNCTION: IMPERIALISM 0x0049d960
void TAdorner::ReadFrom(TStream*) {
  PulseUiInvalidationFlag();
}

// FUNCTION: IMPERIALISM 0x0049d990
void TAdorner::WriteTo(TStream*) {
  PulseUiInvalidationFlag();
}

// FUNCTION: IMPERIALISM 0x0049d9c0
void TAdorner::Draw(TView*, const RECT&) {
  PulseUiInvalidationFlag();
}

// FUNCTION: IMPERIALISM 0x0049d9f0
void TAdorner::ViewChangedFrame(TView*, const RECT&, const RECT&, unsigned char) {
  PulseUiInvalidationFlag();
}

// FUNCTION: IMPERIALISM 0x0049da20
void TAdorner::InvalidateAdorner(TView*) {
  PulseUiInvalidationFlag();
}

// FUNCTION: IMPERIALISM 0x0049da50
void TAdorner::DrawLine(signed char, short, short, short) {
  PulseUiInvalidationFlag();
}

// FUNCTION: IMPERIALISM 0x0049da80
bool TAdorner::DoesAdorn(TView*) {
  PulseUiInvalidationFlag();
  return false;
}
