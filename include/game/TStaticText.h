#pragma once

#include "game/TControl.h"
#include "game/CString.h"

// Static read-only text control (vtable extent matches TControl through slot 0x110).
// VTABLE: IMPERIALISM 0x0064ab58
class TStaticText : public TControl {
public:
  CString text;  // 0x84
  void* field88; // 0x88
  int field8C;   // 0x8c
  int field90;   // 0x90

  TStaticText();
  virtual ~TStaticText() override;

  void CopyCityDialogStateFromSource(TView* source);

  void InitializeTextEntryBaseAndOptionalStringResource(TControl* panel, int* offsetLayout,
                                                        int* sizeLayout, int layoutParam6,
                                                        int layoutParam7, short stringResourceGroup,
                                                        short stringResourceIndex);

  DECLARE_DYNCREATE(TStaticText)

  TObject* ShallowClone() override;                 // 0x20 0x48fc00
  void ApplyRectSlot110(RECT* rectBuffer) override; // 0x110 0x48ffb0

  // TStaticText's five new virtuals beyond TControl (which ends at byte 0x1c0).
  virtual undefined SetTextThemeCodeAndMaybeRefresh(short themeCode,
                                                    char refreshFlag); // 0x1c4 0x48ff70
  virtual undefined
  AssignTextSharedRefIfChangedAndMaybeInvalidate(CString* sharedString,
                                                 char refreshNow); // 0x1c8 0x48fe60
  virtual undefined LoadUiStringAndDispatchViaVslot1C8();          // 0x1cc 0x48fed0
  virtual undefined AssignSharedStringFromField84();               // 0x1d0 0x4294d0
  virtual undefined RenderControlStateTextBySelectionCode();       // 0x1d4 0x4900a0

  void DestroyStaticTextAndReleaseOwnedResources();
};
