#pragma once

#include "game/TStaticText.h"
#include "game/mfc.h"

class CityDialogController;

class CMcWindow;

// VTABLE: IMPERIALISM 0x0064ad90
class TEditText : public TStaticText {
public:
  CMcWindow* field_94; // 0x94 — the live edit CWnd, only present while focused/active
  // Cached font/style resource handle from CreateFontFromPresetAndAttachRegionHandle
  // (0x494130); confirmed polymorphic (freed via virtual dtor dispatch like field_94,
  // not a plain HFONT) but its concrete class isn't recovered yet.
  TObject* field_98;   // 0x98
  short field_9c;      // 0x9c — max character count
  short padding_9e;    // 0x9e

  DECLARE_DYNCREATE(TEditText)
  virtual ~TEditText();

  void Free() override;
  char GetBoolSlot28() override;
  void SetControlValue(int value) override;
  void HandleCityProductionNoOp() override;
  char ActivateCityProductionViewIfAllowed() override;
  void vmethod_0081(int) override;
  void DispatchSlot9CToLinkedChildren() override;
  void CallVoidSlotA0() override;
  void SetEnabled(int enabledState, int refreshFlag) override;
  void ApplyRectSlot110(RECT* rectBuffer) override;
  char DispatchUiMouseMoveToChildren(CPoint* point, int arg2, int arg3, int arg4) override;
  void RecomputeAbsolutePositionRecursive() override;
  void SetTextThemeCodeAndMaybeRefresh(short themeCode, char refreshFlag) override;
  // Third param is pushed by callers (e.g. vmethod_0081) but unused by this
  // body — kept to match the real 3-stack-arg thiscall (confirmed by `ret 0xc`).
  virtual void SetEditSelectionAndScrollCaret(short selStart, short selEnd, int unusedFlag);
  // Returns the control's current text: the live edit window's text if the
  // control is active, otherwise the cached `text` CString. (0x490c70)
  virtual void GetCurrentText(CString* out);
  virtual void InitDialogWindowAndSyncTitleIfChanged(CString* newText, int refreshFlag);

  TEditText();
};

