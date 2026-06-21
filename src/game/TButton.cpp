#include "game/TButton.h"
#include "game/mfc.h"

extern "C" CRuntimeClass PTR_s_TButton_00649618;

undefined4 TemporarilyClearAndRestoreUiInvalidationFlag(void);

// FUNCTION: IMPERIALISM 0x0048eaf0
CRuntimeClass* TButton::GetRuntimeClass() const {
  return &PTR_s_TButton_00649618;
}

// SYNTHETIC: IMPERIALISM 0x0048ec00
// TButton::`scalar deleting destructor'
TButton::~TButton() {}

// FUNCTION: IMPERIALISM 0x0048ecc0
CRuntimeClass* TButton::GetRuntimeClass() const {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048ece0
TButton::TButton() : TControl() {
  TemporarilyClearAndRestoreUiInvalidationFlag();
}

// The scalar deleting destructor is compiler-generated from the virtual dtor.

// SYNTHETIC: IMPERIALISM 0x00492de0
// TButton::`scalar deleting destructor'
