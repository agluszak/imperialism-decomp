#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// VTABLE: IMPERIALISM 0x0064bdd0
class TAdorner : public TObject {
public:
// === BEGIN GENERATED DECLS (TAdorner) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TAdorner)
  virtual ~TAdorner() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override; // slot 0x05 0x49d990
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x49d960
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined WrapperFor_thunk_SetGlobalUiInvalidationFlagAndReturnPrevious_At0049d900(); // slot 0x0a 0x49d900
  virtual undefined WrapperFor_thunk_SetGlobalUiInvalidationFlagAndReturnPrevious_At0049d930(); // slot 0x0b 0x49d930
  virtual undefined WrapperFor_thunk_SetGlobalUiInvalidationFlagAndReturnPrevious_At0049d9c0(); // slot 0x0c 0x49d9c0
  virtual undefined WrapperFor_thunk_SetGlobalUiInvalidationFlagAndReturnPrevious_At0049d9f0(); // slot 0x0d 0x49d9f0
  virtual undefined WrapperFor_thunk_SetGlobalUiInvalidationFlagAndReturnPrevious_At0049da20(); // slot 0x0e 0x49da20
  virtual undefined WrapperFor_thunk_SetGlobalUiInvalidationFlagAndReturnPrevious_At0049da50(); // slot 0x0f 0x49da50
  virtual undefined WrapperFor_thunk_SetGlobalUiInvalidationFlagAndReturnPrevious_At0049da80(); // slot 0x10 0x49da80
// === END GENERATED DECLS (TAdorner) ===

  TAdorner();
};

