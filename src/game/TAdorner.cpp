#include "game/TAdorner.h"

#include "game/global_data_tables.h"

// SYNTHETIC: IMPERIALISM 0x0049d650
// TAdorner::CreateObject

// SYNTHETIC: IMPERIALISM 0x0049d6d0
// TAdorner::GetRuntimeClass

IMPLEMENT_DYNCREATE(TAdorner, TObject)

TAdorner::TAdorner() {}

// Slots 0x0a-0x10 all share one body: pulse the global UI-invalidation flag off and back to
// its prior value (SetGlobalUiInvalidationFlagAndReturnPrevious(0) then
// SetGlobalUiInvalidationFlagAndReturnPrevious(previous)) regardless of argument count --
// the same no-op refresh-barrier idiom TDialogView::EnsureField48Buffer (0x49d880, the
// function immediately preceding this cluster) uses for its own vtable-slot override. This
// is the base class's placeholder default for every adorner draw/layout/hit-test hook;
// TColorFill overrides only slot 0x0c (see TColorFill.cpp) with a real body.

// FUNCTION: IMPERIALISM 0x0049d900
undefined TAdorner::AdornerSlot0A(int) {
  undefined4 previous = SetGlobalUiInvalidationFlagAndReturnPrevious(0);
  return static_cast<undefined>(SetGlobalUiInvalidationFlagAndReturnPrevious(previous));
}

// FUNCTION: IMPERIALISM 0x0049d930
undefined TAdorner::AdornerSlot0B(int) {
  undefined4 previous = SetGlobalUiInvalidationFlagAndReturnPrevious(0);
  return static_cast<undefined>(SetGlobalUiInvalidationFlagAndReturnPrevious(previous));
}

// FUNCTION: IMPERIALISM 0x0049d960
void TAdorner::ReadFrom(TStream* stream) {}

// FUNCTION: IMPERIALISM 0x0049d990
void TAdorner::WriteTo(TStream* stream) {}

// FUNCTION: IMPERIALISM 0x0049d9c0
undefined TAdorner::AdornerSlot0C(int, int) {
  undefined4 previous = SetGlobalUiInvalidationFlagAndReturnPrevious(0);
  return static_cast<undefined>(SetGlobalUiInvalidationFlagAndReturnPrevious(previous));
}

// FUNCTION: IMPERIALISM 0x0049d9f0
undefined TAdorner::AdornerSlot0D(int, int, int, int) {
  undefined4 previous = SetGlobalUiInvalidationFlagAndReturnPrevious(0);
  return static_cast<undefined>(SetGlobalUiInvalidationFlagAndReturnPrevious(previous));
}

// FUNCTION: IMPERIALISM 0x0049da20
undefined TAdorner::AdornerSlot0E(int) {
  undefined4 previous = SetGlobalUiInvalidationFlagAndReturnPrevious(0);
  return static_cast<undefined>(SetGlobalUiInvalidationFlagAndReturnPrevious(previous));
}

// FUNCTION: IMPERIALISM 0x0049da50
undefined TAdorner::AdornerSlot0F(int, int, int, int) {
  undefined4 previous = SetGlobalUiInvalidationFlagAndReturnPrevious(0);
  return static_cast<undefined>(SetGlobalUiInvalidationFlagAndReturnPrevious(previous));
}

// FUNCTION: IMPERIALISM 0x0049da80
undefined TAdorner::AdornerSlot10(int) {
  undefined4 previous = SetGlobalUiInvalidationFlagAndReturnPrevious(0);
  return static_cast<undefined>(SetGlobalUiInvalidationFlagAndReturnPrevious(previous));
}

// SYNTHETIC: IMPERIALISM 0x0049dab0
// TAdorner::`scalar deleting destructor'
TAdorner::~TAdorner() {}
